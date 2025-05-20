"""Resource Server Authentication."""

import base64
import binascii
import contextlib
import logging
from functools import cache

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
from mozilla_django_oidc.contrib.drf import OIDCAuthentication

from .backend import ResourceServerImproperlyConfiguredBackend

logger = logging.getLogger(__name__)


@cache
def get_resource_server_backend():
    """Return the resource server backend class based on the settings."""
    return import_string(settings.OIDC_RS_BACKEND_CLASS)


class ResourceServerAuthentication(OIDCAuthentication):
    """Authenticate clients using the token received from the authorization server."""

    def __init__(self):
        """Require authentication to be configured in order to instantiate."""
        super().__init__()

        try:
            self.backend = get_resource_server_backend()()

        except ImproperlyConfigured as err:
            message = "Resource Server authentication is disabled"
            logger.debug("%s. Exception: %s", message, err)
            self.backend = ResourceServerImproperlyConfiguredBackend()

    def get_access_token(self, request):
        """
        Retrieve and decode the access token from the request.

        This method overrides the 'get_access_token' method from the parent class,
        to support service providers that would base64 encode the bearer token.
        """
        access_token = super().get_access_token(request)

        with contextlib.suppress(binascii.Error, TypeError, UnicodeDecodeError):
            access_token = base64.b64decode(access_token, validate=True).decode("utf-8")

        return access_token

    def authenticate(self, request):
        """
        Authenticate the request and return a tuple of (user, token) or None.

        We override the 'authenticate' method from the parent class to store
        the introspected token audience inside the request.
        """
        result = super().authenticate(request)  # Might raise AuthenticationFailed

        if result is None:  # Case when there is no access token
            return None

        # Note: at this stage, the request is a "drf_request" object
        request.resource_server_token_audience = self.backend.token_origin_audience

        return result
