import time
import uuid
from threading import Thread

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.models import AnonymousUser
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from common.sessions.cache import user_session_manager
from common.utils import get_logger

__all__ = ['UserSessionApi']

logger = get_logger(__name__)


class UserSessionManager:

    def __init__(self, request):
        self.request = request
        self.session = request.session

    def connect(self, client_id=None):
        if client_id:
            return user_session_manager.renew(self.session.session_key, client_id)
        user_session_manager.add_or_increment(self.session.session_key)
        return True

    def disconnect(self, client_id=None):
        if client_id:
            return user_session_manager.release(self.session.session_key, client_id)
        user_session_manager.decrement(self.session.session_key)
        if self.should_delete_session():
            thread = Thread(target=self.delay_delete_session)
            thread.start()
        return True

    def should_delete_session(self):
        return (self.session.modified or settings.SESSION_SAVE_EVERY_REQUEST) and \
            not self.session.is_empty() and \
            self.session.get_expire_at_browser_close() and \
            not user_session_manager.check_active(self.session.session_key)

    def delay_delete_session(self):
        timeout = 6
        check_interval = 0.5

        start_time = time.time()
        while time.time() - start_time < timeout:
            time.sleep(check_interval)
            if user_session_manager.check_active(self.session.session_key):
                return

        logout(self.request)


class UserSessionApi(generics.RetrieveDestroyAPIView):
    permission_classes = ()

    @staticmethod
    def get_client_id(request, required=True):
        client_id = request.data.get('client_id')
        if not client_id and not required:
            return None
        try:
            return str(uuid.UUID(client_id))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValidationError({'client_id': 'A valid client ID is required.'}) from exc

    @staticmethod
    def get_response_data():
        return {
            'ok': True,
            'heartbeat_interval': user_session_manager.HEARTBEAT_INTERVAL,
            'lease_ttl': user_session_manager.LEASE_TTL,
        }

    def retrieve(self, request, *args, **kwargs):
        if isinstance(request.user, AnonymousUser):
            return Response(status=status.HTTP_403_FORBIDDEN)

        UserSessionManager(request).connect()
        return Response(status=status.HTTP_200_OK, data=self.get_response_data())

    def post(self, request, *args, **kwargs):
        if isinstance(request.user, AnonymousUser):
            return Response(status=status.HTTP_403_FORBIDDEN)

        client_id = self.get_client_id(request)
        connected = UserSessionManager(request).connect(client_id)
        if connected is None:
            return Response(status=status.HTTP_403_FORBIDDEN)
        data = self.get_response_data()
        data['ok'] = connected
        return Response(status=status.HTTP_200_OK, data=data)

    def destroy(self, request, *args, **kwargs):
        if isinstance(request.user, AnonymousUser):
            return Response(status=status.HTTP_403_FORBIDDEN)

        client_id = self.get_client_id(request, required=False)
        UserSessionManager(request).disconnect(client_id)
        return Response(status=status.HTTP_200_OK, data={'ok': True})
