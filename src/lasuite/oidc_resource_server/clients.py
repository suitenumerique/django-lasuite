"""Resource Server Clients classes."""

import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from joserfc.jwk import KeySet


class AuthorizationServerClient:
    """
    Client for interacting with an OAuth 2.0 authorization server.

    An authorization server issues access tokens to client applications after authenticating
    and obtaining authorization from the resource owner. It also provides endpoints for token
    introspection and JSON Web Key Sets (JWKS) to validate and decode tokens.

    This client facilitates communication with the authorization server, including:
    - Fetching token introspection responses.
    - Fetching JSON Web Key Sets (JWKS) for token validation.
    - Setting appropriate headers for secure communication as recommended by RFC drafts.
    """

    _header_accept = "application/json"

    def __init__(self):
        """Require at a minimum url, url_jwks and url_introspection."""
        self.url = settings.OIDC_OP_URL
        self._verify_ssl = settings.OIDC_VERIFY_SSL
        self._timeout = settings.OIDC_TIMEOUT
        self._proxy = settings.OIDC_PROXY
        self._url_introspection = settings.OIDC_OP_INTROSPECTION_ENDPOINT

        if not self.url or not self._url_introspection:
            raise ImproperlyConfigured(f"Could not instantiate {self.__class__.__name__}, some parameters are missing.")

    @property
    def _introspection_headers(self):
        """
        Get HTTP header for the introspection request.

        Notify the authorization server that we expect a signed and encrypted response
        by setting the appropriate 'Accept' header.

        This follows the recommendation from the draft RFC:
        https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response-12.
        """
        return {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": self._header_accept,
        }

    def get_introspection(self, client_id, client_secret, token):
        """Retrieve introspection response about a token."""
        response = requests.post(
            self._url_introspection,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "token": token,
            },
            headers=self._introspection_headers,
            verify=self._verify_ssl,
            timeout=self._timeout,
            proxies=self._proxy,
        )
        response.raise_for_status()
        return response.text

    def get_jwks(self):
        """Retrieve Authorization Server JWKS."""
        raise RuntimeError("get_jwks must not be used in JSON introspection mode.")

    def import_public_keys(self):
        """Retrieve and import Authorization Server JWKS."""
        raise RuntimeError("import_public_keys must not be used in JSON introspection mode.")


class JWTAuthorizationServerClient(AuthorizationServerClient):
    """
    Client for interacting with an OAuth 2.0 authorization server.

    This client is specifically designed for authorization servers that use JWTs (JSON Web Tokens)
    """

    _header_accept = "application/token-introspection+jwt"

    def __init__(self):
        """Require at a minimum url, url_jwks and url_introspection."""
        super().__init__()
        self._url_jwks = settings.OIDC_OP_JWKS_ENDPOINT

        if not self._url_jwks:
            raise ImproperlyConfigured(f"Could not instantiate {self.__class__.__name__}, some parameters are missing.")

    def get_jwks(self):
        """Retrieve Authorization Server JWKS."""
        response = requests.get(
            self._url_jwks,
            verify=self._verify_ssl,
            timeout=self._timeout,
            proxies=self._proxy,
        )
        response.raise_for_status()
        return response.json()

    def import_public_keys(self):
        """Retrieve and import Authorization Server JWKS."""
        jwks = self.get_jwks()
        return KeySet.import_key_set(jwks)
