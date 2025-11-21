"""Resource Server Authentication."""

import base64
import binascii
import contextlib
import logging
from functools import cache

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.utils.module_loading import import_string
from mozilla_django_oidc.contrib.drf import OIDCAuthentication
from mozilla_django_oidc.utils import parse_www_authenticate_header
from requests.exceptions import HTTPError
from rest_framework import exceptions
from rest_framework.status import HTTP_401_UNAUTHORIZED

from .backend import ResourceServerBackend, ResourceServerImproperlyConfiguredBackend

logger = logging.getLogger(__name__)


@cache
def get_resource_server_backend() -> type[ResourceServerBackend]:
    """Return the resource server backend class based on the settings."""
    return import_string(settings.OIDC_RS_BACKEND_CLASS)


class ResourceServerAuthentication(OIDCAuthentication):
    """
    Authenticate clients using the token received from the authorization server.

    We still inherit from OIDCAuthentication for the basic token extraction,
    but the authenticate method is fully overridden.
    """

    def __init__(self):
        """Require authentication to be configured in order to instantiate."""
        try:
            super().__init__(backend=get_resource_server_backend()())
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

        We fully override the 'authenticate' method from the parent class:
         - to be able to introspect the access token earlier (doing it in the
           get_user method would be too late);
         - to store the introspected token audience inside the request to allow the
           views to use it later (for permission restriction).

        The implementation is still highly inspired from the parent class.
        """
        access_token = self.get_access_token(request)

        if not access_token:
            # Defer to next authentication backend
            return None

        # Custom addition: introspect the access token to ensure it's valid
        # and retrieve user info.
        try:
            user_info = self.backend.get_user_info_with_introspection(access_token)
        except HTTPError as exc:
            resp = exc.response

            # If the oidc provider returns 401, it means the token is invalid or that
            # the introspection is not allowed.
            # In that case, we want to return the upstream error message (which
            # we can get from the www-authentication header) in the response.
            if resp.status_code == HTTP_401_UNAUTHORIZED and "www-authenticate" in resp.headers:
                data = parse_www_authenticate_header(resp.headers["www-authenticate"])
                raise exceptions.AuthenticationFailed(
                    data.get("error_description", "no error description in www-authenticate")
                ) from exc

            # for all other http errors, just re-raise the exception.
            raise

        try:
            user = self.backend.get_or_create_user(access_token, None, user_info)

        except SuspiciousOperation as exc:
            logger.info("Login failed: %s", exc)
            raise exceptions.AuthenticationFailed("Login failed") from exc

        if not user:
            msg = "Login failed: No user found for the given access token."
            raise exceptions.AuthenticationFailed(msg)

        # Custom addition: store the token audience in the request
        # Note: at this stage, the request is a "drf_request" object
        request.resource_server_token_audience = self.backend.token_origin_audience

        return user, user_info
