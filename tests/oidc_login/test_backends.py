"""Unit tests for the Authentication Backends."""

import contextlib
import re
from unittest.mock import MagicMock

import pytest
import responses
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation

from lasuite.oidc_login.backends import OIDCAuthenticationBackend, get_oidc_refresh_token, store_oidc_refresh_token

from .. import factories

pytestmark = pytest.mark.django_db

User = get_user_model()


def test_oidc_refresh_token_session_store(settings):
    """Test that the OIDC refresh token is stored and retrieved from the session."""
    settings.OIDC_STORE_REFRESH_TOKEN = True
    session = {}

    with pytest.raises(ValueError, match="OIDC_STORE_REFRESH_TOKEN_KEY setting is required."):
        store_oidc_refresh_token(session, "test-refresh-token")

    settings.OIDC_STORE_REFRESH_TOKEN_KEY = Fernet.generate_key()

    store_oidc_refresh_token(session, "test-refresh-token")
    assert session["oidc_refresh_token"] is not None
    assert session["oidc_refresh_token"] != "test-refresh-token"

    assert get_oidc_refresh_token(session) == "test-refresh-token"


def test_authentication_getter_existing_user_no_email(django_assert_num_queries, monkeypatch):
    """If an existing user matches the user's info sub, the user should be returned."""
    klass = OIDCAuthenticationBackend()
    user = factories.UserFactory()

    def get_userinfo_mocked(*args):
        return {"sub": user.sub}

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    with django_assert_num_queries(1):
        authenticated_user = klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert user == authenticated_user


def test_authentication_getter_existing_user_with_email(django_assert_num_queries, monkeypatch):
    """When the user's info contains an email and targets an existing user,."""
    klass = OIDCAuthenticationBackend()

    user = factories.UserFactory(name="John Doe")

    def get_userinfo_mocked(*args):
        return {
            "sub": user.sub,
            "email": user.email,
            "first_name": "John",
            "last_name": "Doe",
        }

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    # Only 1 query because email and names have not changed
    with django_assert_num_queries(1):
        authenticated_user = klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert user == authenticated_user


@pytest.mark.parametrize(
    ("first_name", "last_name", "email"),
    [
        ("Jack", "Doe", "john.doe@example.com"),
        ("John", "Duy", "john.doe@example.com"),
        ("John", "Doe", "jack.duy@example.com"),
        ("Jack", "Duy", "jack.duy@example.com"),
    ],
)
def test_authentication_getter_existing_user_change_fields(
    first_name, last_name, email, django_assert_num_queries, monkeypatch
):
    """It should update the email or name fields on the user when they change."""
    klass = OIDCAuthenticationBackend()
    user = factories.UserFactory(
        name="John Doe",
        email="john.doe@example.com",
    )

    def get_userinfo_mocked(*args):
        return {
            "sub": user.sub,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
        }

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    # One and only one additional update query when a field has changed
    with django_assert_num_queries(2):
        authenticated_user = klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert user == authenticated_user
    user.refresh_from_db()
    assert user.email == email
    assert user.name == f"{first_name:s} {last_name:s}"


def test_authentication_getter_existing_user_keep_fields(django_assert_num_queries, monkeypatch):
    """Falsy values in claim should not update the user's fields."""
    klass = OIDCAuthenticationBackend()
    user = factories.UserFactory(
        name="John Doe",
        email="john.doe@example.com",
    )

    def get_userinfo_mocked(*args):
        return {
            "sub": user.sub,
            "email": None,
            "first_name": "",
            "last_name": "",
        }

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    # No field changed no more query
    with django_assert_num_queries(1):
        authenticated_user = klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert user == authenticated_user
    user.refresh_from_db()
    assert user.email == "john.doe@example.com"
    assert user.name == "John Doe"


def test_authentication_getter_existing_user_via_email(django_assert_num_queries, monkeypatch):
    """
    If an existing user doesn't match the sub but matches the email,
    the user should be returned.
    """
    klass = OIDCAuthenticationBackend()
    db_user = factories.UserFactory()

    def get_userinfo_mocked(*args):
        return {"sub": "123", "email": db_user.email}

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    with django_assert_num_queries(3):  # user by email + user by sub + update sub
        user = klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert user == db_user


def test_authentication_getter_existing_user_no_fallback_to_email(settings, monkeypatch):
    """
    When the "OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION" setting is set to False,
    the system should not match users by email, even if the email matches.
    """
    klass = OIDCAuthenticationBackend()
    db_user = factories.UserFactory()

    # Set the setting to False
    settings.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = False

    def get_userinfo_mocked(*args):
        return {"sub": "123", "email": db_user.email}

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    user = klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    # Since the sub doesn't match, it should create a new user
    assert User.objects.count() == 2
    assert user != db_user
    assert user.sub == "123"


def test_authentication_getter_new_user_with_email(monkeypatch):
    """
    If no user matches the user's info sub, a user should be created.
    User's email and name should be set on the user.
    """
    klass = OIDCAuthenticationBackend()
    email = "jane.doe@example.com"

    def get_userinfo_mocked(*args):
        return {"sub": "123", "email": email, "first_name": "John", "last_name": "Doe"}

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    user = klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert user.sub == "123"
    assert user.email == email
    assert user.name == "John Doe"
    assert user.has_usable_password() is False
    assert User.objects.count() == 1


def test_models_oidc_user_getter_invalid_token(django_assert_num_queries, monkeypatch):
    """The user's info doesn't contain a sub."""
    klass = OIDCAuthenticationBackend()

    def get_userinfo_mocked(*args):
        return {
            "test": "123",
        }

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    with (
        django_assert_num_queries(0),
        pytest.raises(
            SuspiciousOperation,
            match="Claims verification failed",
        ),
    ):
        klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert User.objects.exists() is False


def test_authentication_getter_existing_disabled_user_via_sub(django_assert_num_queries, monkeypatch):
    """
    If an existing user matches the sub but is disabled,
    an error should be raised and a user should not be created.
    """
    klass = OIDCAuthenticationBackend()
    db_user = factories.UserFactory(name="John Doe", is_active=False)

    def get_userinfo_mocked(*args):
        return {
            "sub": db_user.sub,
            "email": db_user.email,
            "first_name": "John",
            "last_name": "Doe",
        }

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    with (
        django_assert_num_queries(1),
        pytest.raises(SuspiciousOperation, match="User account is disabled"),
    ):
        klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert User.objects.count() == 1


def test_authentication_getter_existing_disabled_user_via_email(django_assert_num_queries, monkeypatch):
    """
    If an existing user does not matches the sub but match the email and is disabled,
    an error should be raised and a user should not be created.
    """
    klass = OIDCAuthenticationBackend()
    db_user = factories.UserFactory(name="John Doe", is_active=False)

    def get_userinfo_mocked(*args):
        return {
            "sub": "random",
            "email": db_user.email,
            "first_name": "John",
            "last_name": "Doe",
        }

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    with (
        django_assert_num_queries(2),
        pytest.raises(SuspiciousOperation, match="User account is disabled"),
    ):
        klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert User.objects.count() == 1


@responses.activate
def test_authentication_session_tokens(django_assert_num_queries, monkeypatch, rf, settings):
    """Test the session contains oidc_refresh_token and oidc_access_token after authentication."""
    settings.OIDC_OP_TOKEN_ENDPOINT = "http://oidc.endpoint.test/token"
    settings.OIDC_OP_USER_ENDPOINT = "http://oidc.endpoint.test/userinfo"
    settings.OIDC_OP_JWKS_ENDPOINT = "http://oidc.endpoint.test/jwks"
    settings.OIDC_STORE_ACCESS_TOKEN = True
    settings.OIDC_STORE_REFRESH_TOKEN = True
    settings.OIDC_STORE_REFRESH_TOKEN_KEY = Fernet.generate_key()

    klass = OIDCAuthenticationBackend()
    request = rf.get("/some-url", {"state": "test-state", "code": "test-code"})
    request.session = {}

    def verify_token_mocked(*args, **kwargs):
        return {"sub": "123", "email": "test@example.com"}

    monkeypatch.setattr(OIDCAuthenticationBackend, "verify_token", verify_token_mocked)

    responses.add(
        responses.POST,
        re.compile(settings.OIDC_OP_TOKEN_ENDPOINT),
        json={
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
        },
        status=200,
    )

    responses.add(
        responses.GET,
        re.compile(settings.OIDC_OP_USER_ENDPOINT),
        json={"sub": "123", "email": "test@example.com"},
        status=200,
    )

    with django_assert_num_queries(3):
        user = klass.authenticate(
            request,
            code="test-code",
            nonce="test-nonce",
            code_verifier="test-code-verifier",
        )

    assert user is not None
    assert request.session["oidc_access_token"] == "test-access-token"
    assert get_oidc_refresh_token(request.session) == "test-refresh-token"


def test_authentication_get_userinfo_default_setting(settings):
    """Test OIDCAuthenticationBackend default behavior regarding userinfo is "auto"."""
    # explicitly remove setting definition
    with contextlib.suppress(AttributeError):
        del settings.OIDC_OP_USER_ENDPOINT_FORMAT

    oidc_backend = OIDCAuthenticationBackend()
    assert oidc_backend.OIDC_OP_USER_ENDPOINT_FORMAT.name == "AUTO"


@responses.activate
def test_authentication_get_userinfo_auto_response(monkeypatch, settings):
    """Test get_userinfo method with a JSON or JWT response."""
    settings.OIDC_OP_USER_ENDPOINT = "http://oidc.endpoint.test/userinfo"

    settings.OIDC_OP_USER_ENDPOINT_FORMAT = "AUTO"
    oidc_backend = OIDCAuthenticationBackend()

    # Authentication should work if the response is JSON
    responses.get(
        settings.OIDC_OP_USER_ENDPOINT,
        json={
            "first_name": "John",
            "last_name": "Doe",
            "email": "john.doe@example.com",
        },
        status=200,
    )
    result = oidc_backend.get_userinfo("fake_access_token", None, None)
    assert result["first_name"] == "John"
    assert result["last_name"] == "Doe"
    assert result["email"] == "john.doe@example.com"

    # Authentication should work if the response is JWT (requires content_type in auto mode)
    responses.get(settings.OIDC_OP_USER_ENDPOINT, body="fake.jwt.token", status=200, content_type="application/jwt")

    def mock_verify_token(self, token):  # pylint: disable=unused-argument
        return {
            "first_name": "Jane",
            "last_name": "Doe",
            "email": "jane.doe@example.com",
        }

    monkeypatch.setattr(OIDCAuthenticationBackend, "verify_token", mock_verify_token)
    result = oidc_backend.get_userinfo("fake_access_token", None, None)

    assert result["first_name"] == "Jane"
    assert result["last_name"] == "Doe"
    assert result["email"] == "jane.doe@example.com"

    # Authentication should work if the response is JWT with params in content type
    responses.get(
        settings.OIDC_OP_USER_ENDPOINT, body="fake.jwt.token", status=200, content_type="application/JWT; charset=utf-8"
    )

    def mock_verify_token(self, token):  # pylint: disable=unused-argument
        return {
            "first_name": "Jane",
            "last_name": "Doe",
            "email": "jane.doe@example.com",
        }

    monkeypatch.setattr(OIDCAuthenticationBackend, "verify_token", mock_verify_token)
    result = oidc_backend.get_userinfo("fake_access_token", None, None)

    assert result["first_name"] == "Jane"
    assert result["last_name"] == "Doe"
    assert result["email"] == "jane.doe@example.com"


@responses.activate
def test_authentication_get_userinfo_json_response(settings):
    """Test get_userinfo method with a JSON response."""
    settings.OIDC_OP_USER_ENDPOINT = "http://oidc.endpoint.test/userinfo"

    responses.add(
        responses.GET,
        settings.OIDC_OP_USER_ENDPOINT,
        json={
            "first_name": "John",
            "last_name": "Doe",
            "email": "john.doe@example.com",
        },
        status=200,
    )

    # We should raise if we expect JWT but get JSON
    settings.OIDC_OP_USER_ENDPOINT_FORMAT = "JWT"
    oidc_backend = OIDCAuthenticationBackend()
    with pytest.raises(SuspiciousOperation, match="User info response was not valid JWT"):
        oidc_backend.get_userinfo("fake_access_token", None, None)

    # We should not raise if we expect JSON and get JSON
    settings.OIDC_OP_USER_ENDPOINT_FORMAT = "JSON"
    oidc_backend = OIDCAuthenticationBackend()
    result = oidc_backend.get_userinfo("fake_access_token", None, None)

    assert result["first_name"] == "John"
    assert result["last_name"] == "Doe"
    assert result["email"] == "john.doe@example.com"


@responses.activate
def test_authentication_get_userinfo_token_response(monkeypatch, settings):
    """Test get_userinfo method with a token response."""
    settings.OIDC_OP_USER_ENDPOINT = "http://oidc.endpoint.test/userinfo"

    responses.add(responses.GET, settings.OIDC_OP_USER_ENDPOINT, body="fake.jwt.token", status=200)

    def mock_verify_token(self, token):  # pylint: disable=unused-argument
        return {
            "first_name": "Jane",
            "last_name": "Doe",
            "email": "jane.doe@example.com",
        }

    monkeypatch.setattr(OIDCAuthenticationBackend, "verify_token", mock_verify_token)

    # We should raise if do not expect JWT but get JWT
    settings.OIDC_OP_USER_ENDPOINT_FORMAT = "JSON"
    oidc_backend = OIDCAuthenticationBackend()
    with pytest.raises(SuspiciousOperation, match="User info response was not valid JSON"):
        oidc_backend.get_userinfo("fake_access_token", None, None)

    # We should not raise if we expect JWT and get JWT
    settings.OIDC_OP_USER_ENDPOINT_FORMAT = "JWT"
    oidc_backend = OIDCAuthenticationBackend()
    result = oidc_backend.get_userinfo("fake_access_token", None, None)

    assert result["first_name"] == "Jane"
    assert result["last_name"] == "Doe"
    assert result["email"] == "jane.doe@example.com"


@responses.activate
def test_authentication_get_userinfo_invalid_response(settings):
    """
    Test get_userinfo method with an invalid JWT response that
    causes verify_token to raise an error.
    """
    settings.OIDC_OP_USER_ENDPOINT = "http://oidc.endpoint.test/userinfo"
    settings.OIDC_OP_USER_ENDPOINT_FORMAT = "JWT"

    responses.add(responses.GET, settings.OIDC_OP_USER_ENDPOINT, body="fake.jwt.token", status=200)

    oidc_backend = OIDCAuthenticationBackend()

    with pytest.raises(
        SuspiciousOperation,
        match="User info response was not valid JWT",
    ):
        oidc_backend.get_userinfo("fake_access_token", None, None)


def test_authentication_verify_claims_default(django_assert_num_queries, monkeypatch):
    """The sub claim should be mandatory by default."""
    klass = OIDCAuthenticationBackend()

    def get_userinfo_mocked(*args):
        return {
            "test": "123",
        }

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    with (
        django_assert_num_queries(0),
        pytest.raises(
            SuspiciousOperation,
            match="Claims verification failed",
        ),
    ):
        klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert User.objects.exists() is False


@pytest.mark.parametrize(
    ("essential_claims", "missing_claims"),
    [
        (["email", "sub", "last_name"], ["email", "sub"]),
        (["Email", "sub", "last_name"], ["Email", "sub"]),  # Case sensitivity
        (["email"], ["email", "sub"]),  # sub is mandatory by default
    ],
)
def test_authentication_verify_claims_essential_missing(  # noqa: PLR0913
    essential_claims,
    missing_claims,
    caplog,
    django_assert_num_queries,
    monkeypatch,
    settings,
):
    """Ensure SuspiciousOperation is raised if essential claims are missing."""
    settings.OIDC_OP_USER_ENDPOINT = "http://oidc.endpoint.test/userinfo"
    settings.OIDC_USERINFO_ESSENTIAL_CLAIMS = essential_claims

    klass = OIDCAuthenticationBackend()

    def get_userinfo_mocked(*args):
        return {
            "last_name": "Doe",
        }

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    caplog.clear()
    with (
        django_assert_num_queries(0),
        pytest.raises(
            SuspiciousOperation,
            match="Claims verification failed",
        ),
    ):
        klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert User.objects.exists() is False

    assert "Missing essential claims:" in caplog.text
    for claim in missing_claims:
        assert claim in caplog.text


def test_models_oidc_user_getter_empty_sub(django_assert_num_queries, monkeypatch):
    """The user's info contains a sub, but it's an empty string."""
    klass = OIDCAuthenticationBackend()

    def get_userinfo_mocked(*args):
        return {"test": "123", "sub": ""}

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    with (
        django_assert_num_queries(0),
        pytest.raises(
            SuspiciousOperation,
            match="User info contained no recognizable user identification",
        ),
    ):
        klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert User.objects.exists() is False


def test_authentication_verify_claims_success(django_assert_num_queries, monkeypatch, settings):
    """Ensure user is authenticated when all essential claims are present."""
    settings.OIDC_OP_USER_ENDPOINT = "http://oidc.endpoint.test/userinfo"
    settings.OIDC_USERINFO_ESSENTIAL_CLAIMS = ["email", "last_name"]

    klass = OIDCAuthenticationBackend()

    def get_userinfo_mocked(*args):
        return {
            "email": "john.doe@example.com",
            "last_name": "Doe",
            "sub": "123",
        }

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    with django_assert_num_queries(3):
        user = klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    assert User.objects.filter(id=user.id).exists()

    assert user.sub == "123"
    assert user.name == "Doe"
    assert user.email == "john.doe@example.com"


@pytest.mark.django_db
def test_post_get_or_create_user_called_for_existing_user(monkeypatch, django_assert_num_queries):
    """Test that post_get_or_create_user is called for an existing user."""
    klass = OIDCAuthenticationBackend()
    user = factories.UserFactory()

    # Mock the post_get_or_create_user method
    mock_post_method = MagicMock()
    monkeypatch.setattr(OIDCAuthenticationBackend, "post_get_or_create_user", mock_post_method)

    def get_userinfo_mocked(*args):
        return {"sub": user.sub}

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    with django_assert_num_queries(1):
        klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    mock_post_method.assert_called_once_with(user, {"sub": user.sub, "email": None, "name": None}, False)


@pytest.mark.django_db
def test_post_get_or_create_user_called_for_new_user(monkeypatch, django_assert_num_queries):
    """Test that post_get_or_create_user is called for a newly created user."""
    klass = OIDCAuthenticationBackend()

    def get_userinfo_mocked(*args):
        return {"sub": "new-sub", "email": "new@example.com", "first_name": "New", "last_name": "User"}

    monkeypatch.setattr(OIDCAuthenticationBackend, "get_userinfo", get_userinfo_mocked)

    # Mock the post_get_or_create_user method
    mock_post_method = MagicMock()
    monkeypatch.setattr(OIDCAuthenticationBackend, "post_get_or_create_user", mock_post_method)

    with django_assert_num_queries(3):  # Create user queries
        user = klass.get_or_create_user(access_token="test-token", id_token=None, payload=None)

    mock_post_method.assert_called_once_with(
        user,
        {"sub": "new-sub", "email": "new@example.com", "name": "New User"},
        True,
    )
