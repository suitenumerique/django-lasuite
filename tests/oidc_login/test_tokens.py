"""Tests for get_fresh_access_token."""

import time
from unittest.mock import MagicMock

import factories
import pytest
import responses
from cryptography.fernet import Fernet
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory

from lasuite.oidc_login.backends import get_cipher_suite, get_oidc_refresh_token, store_oidc_refresh_token
from lasuite.oidc_login.tokens import get_fresh_access_token

pytestmark = pytest.mark.django_db

TOKEN_ENDPOINT = "https://auth.example.com/token"


@pytest.fixture(name="oidc_settings")
def fixture_oidc_settings(settings):
    """Store the tokens in the session and refresh them at a known endpoint."""
    settings.OIDC_OP_TOKEN_ENDPOINT = TOKEN_ENDPOINT
    settings.OIDC_OP_AUTHORIZATION_ENDPOINT = "https://auth.example.com/authorize"
    settings.OIDC_RP_CLIENT_ID = "client_id"
    settings.OIDC_RP_CLIENT_SECRET = "client_secret"
    settings.OIDC_AUTHENTICATION_CALLBACK_URL = "oidc_authentication_callback"
    settings.OIDC_RP_SCOPES = "openid email"
    settings.OIDC_STORE_ACCESS_TOKEN = True
    settings.OIDC_STORE_REFRESH_TOKEN = True
    settings.OIDC_STORE_REFRESH_TOKEN_KEY = Fernet.generate_key()
    get_cipher_suite.cache_clear()
    yield settings
    get_cipher_suite.cache_clear()


def _request(access_token="access_token", expires_in=100, refresh_token=None):
    """Build a logged-in request whose session holds the given tokens."""
    request = RequestFactory().get("/search")
    request.user = factories.UserFactory()
    SessionMiddleware(MagicMock()).process_request(request)
    request.session["oidc_access_token"] = access_token
    request.session["oidc_id_token_expiration"] = time.time() + expires_in
    if refresh_token:
        store_oidc_refresh_token(request.session, refresh_token)
    return request


def test_tokens_not_stored(settings):
    """Without stored tokens there is nothing to call a resource server with."""
    settings.OIDC_STORE_ACCESS_TOKEN = False

    assert get_fresh_access_token(_request()) is None


@pytest.mark.usefixtures("oidc_settings")
def test_valid_token():
    """A token that hasn't expired is returned as is."""
    assert get_fresh_access_token(_request(access_token="valid")) == "valid"


@pytest.mark.usefixtures("oidc_settings")
def test_expired_token_without_refresh_token():
    """An expired token that can't be refreshed gives None, not a 401."""
    assert get_fresh_access_token(_request(expires_in=-100)) is None


@pytest.mark.usefixtures("oidc_settings")
@responses.activate
def test_expired_token_refreshed():
    """An expired token is refreshed and the new one returned and stored."""
    responses.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={"access_token": "new_access", "refresh_token": "new_refresh", "expires_in": 300},
    )
    request = _request(expires_in=-100, refresh_token="refresh")

    assert get_fresh_access_token(request) == "new_access"
    assert request.session["oidc_access_token"] == "new_access"
    assert get_oidc_refresh_token(request.session) == "new_refresh"


@pytest.mark.usefixtures("oidc_settings")
@responses.activate
def test_expired_token_refresh_refused():
    """A refused refresh gives None instead of logging the user out."""
    responses.add(responses.POST, TOKEN_ENDPOINT, status=400, json={"error": "invalid_grant"})

    assert get_fresh_access_token(_request(expires_in=-100, refresh_token="refresh")) is None
