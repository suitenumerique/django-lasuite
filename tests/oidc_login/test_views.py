"""Unit tests for the Authentication Views."""

import json
import time
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
import responses
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.sessions.models import Session
from django.core.exceptions import SuspiciousOperation
from django.test import RequestFactory
from django.urls import reverse
from django.utils import crypto
from joserfc import jwt
from joserfc.jwk import RSAKey
from rest_framework.test import APIClient

from lasuite.oidc_login.views import (
    OIDCAuthenticationCallbackView,
    OIDCAuthenticationRequestView,
    OIDCBackChannelLogoutView,
    OIDCLogoutCallbackView,
    OIDCLogoutView,
)
from tests import factories

UserModel = get_user_model()

pytestmark = pytest.mark.django_db


def test_view_logout_anonymous(settings):
    """
    Anonymous users calling the logout url,
    should be redirected to the specified LOGOUT_REDIRECT_URL.
    """
    settings.ALLOW_LOGOUT_GET_METHOD = True
    settings.LOGOUT_REDIRECT_URL = "/example-logout"

    url = reverse("oidc_logout_custom")
    response = APIClient().get(url)

    assert response.status_code == 302
    assert response.url == "/example-logout"


@mock.patch.object(OIDCLogoutView, "construct_oidc_logout_url", return_value="/example-logout")
def test_view_logout(mocked_oidc_logout_url, settings):
    """Authenticated users should be redirected to OIDC provider for logout."""
    settings.ALLOW_LOGOUT_GET_METHOD = True

    user = factories.UserFactory()

    client = APIClient()
    client.force_login(user)

    url = reverse("oidc_logout_custom")
    response = client.get(url)

    mocked_oidc_logout_url.assert_called_once()

    assert response.status_code == 302
    assert response.url == "/example-logout"


@mock.patch.object(OIDCLogoutView, "construct_oidc_logout_url", return_value="/default-redirect-logout")
def test_view_logout_no_oidc_provider(mocked_oidc_logout_url, settings):
    """Authenticated users should be logged out when no OIDC provider is available."""
    settings.ALLOW_LOGOUT_GET_METHOD = True
    settings.LOGOUT_REDIRECT_URL = "/default-redirect-logout"

    user = factories.UserFactory()

    client = APIClient()
    client.force_login(user)

    url = reverse("oidc_logout_custom")

    with mock.patch("mozilla_django_oidc.views.auth.logout") as mock_logout:
        response = client.get(url)
        mocked_oidc_logout_url.assert_called_once()
        mock_logout.assert_called_once()

    assert response.status_code == 302
    assert response.url == "/default-redirect-logout"


def test_view_logout_callback_anonymous(settings):
    """
    Anonymous users calling the logout callback url,
    should be redirected to the specified LOGOUT_REDIRECT_URL.
    """
    settings.LOGOUT_REDIRECT_URL = "/example-logout"

    url = reverse("oidc_logout_callback")
    response = APIClient().get(url)

    assert response.status_code == 302
    assert response.url == "/example-logout"


def test_view_logout_callback_without_state(settings):
    """
    Logout callback without state parameter should redirect gracefully.
    This handles SSO providers that send preflight requests without state.
    """
    settings.LOGOUT_REDIRECT_URL = "/example-logout"
    user = factories.UserFactory()

    request = RequestFactory().get("/logout-callback/")
    request.user = user

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    request.session["oidc_states"] = {"some_state": {}}
    request.session.save()

    callback_view = OIDCLogoutCallbackView.as_view()
    response = callback_view(request)

    assert response.status_code == 302
    assert response.url == "/example-logout"
    # State should remain in session since no state was provided
    assert request.session["oidc_states"] == {"some_state": {}}


@pytest.mark.parametrize(
    "initial_oidc_states",
    [{}, {"other_state": "foo"}],
)
def test_view_logout_persist_state(initial_oidc_states):
    """State value should be persisted in session's data."""
    user = factories.UserFactory()

    request = RequestFactory().request()
    request.user = user

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    if initial_oidc_states:
        request.session["oidc_states"] = initial_oidc_states
        request.session.save()

    mocked_state = "mock_state"

    OIDCLogoutView().persist_state(request, mocked_state)

    assert "oidc_states" in request.session
    assert request.session["oidc_states"] == {
        "mock_state": {},
        **initial_oidc_states,
    }


@mock.patch.object(OIDCLogoutView, "persist_state")
@mock.patch.object(crypto, "get_random_string", return_value="mocked_state")
def test_view_logout_construct_oidc_logout_url(mocked_get_random_string, mocked_persist_state, settings):
    """Should construct the logout URL to initiate the logout flow with the OIDC provider."""
    settings.OIDC_OP_LOGOUT_ENDPOINT = "/example-logout"

    user = factories.UserFactory()

    request = RequestFactory().request()
    request.user = user

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    request.session["oidc_id_token"] = "mocked_oidc_id_token"
    request.session.save()

    redirect_url = OIDCLogoutView().construct_oidc_logout_url(request)

    mocked_persist_state.assert_called_once()
    mocked_get_random_string.assert_called_once()

    params = parse_qs(urlparse(redirect_url).query)

    assert params["id_token_hint"][0] == "mocked_oidc_id_token"
    assert params["state"][0] == "mocked_state"

    url = reverse("oidc_logout_callback")
    assert url in params["post_logout_redirect_uri"][0]


def test_view_logout_construct_oidc_logout_url_none_id_token(settings):
    """
    If no ID token is available in the session,
    the user should be redirected to the final URL.
    """
    settings.LOGOUT_REDIRECT_URL = "/"
    user = factories.UserFactory()

    request = RequestFactory().request()
    request.user = user

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    redirect_url = OIDCLogoutView().construct_oidc_logout_url(request)

    assert redirect_url == "/"


@pytest.mark.parametrize(
    "initial_state",
    [None, {"other_state": "foo"}],
)
def test_view_logout_callback_wrong_state(initial_state):
    """Should raise an error if OIDC state doesn't match session data."""
    user = factories.UserFactory()

    request = RequestFactory().get("/logout-callback/", data={"state": "invalid_state"})
    request.user = user

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    if initial_state:
        request.session["oidc_states"] = initial_state
        request.session.save()

    callback_view = OIDCLogoutCallbackView.as_view()

    with pytest.raises(SuspiciousOperation) as excinfo:
        callback_view(request)

    assert str(excinfo.value) == "OIDC callback state not found in session `oidc_states`!"


def test_view_logout_callback(settings):
    """If state matches, callback should clear OIDC state and redirects."""
    settings.LOGOUT_REDIRECT_URL = "/example-logout"
    user = factories.UserFactory()

    request = RequestFactory().get("/logout-callback/", data={"state": "mocked_state"})
    request.user = user

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    mocked_state = "mocked_state"

    request.session["oidc_states"] = {mocked_state: {}}
    request.session.save()

    callback_view = OIDCLogoutCallbackView.as_view()

    with mock.patch("mozilla_django_oidc.views.auth.logout") as mock_logout:

        def clear_user(request):
            # Assert state is cleared prior to logout
            assert request.session["oidc_states"] == {}
            request.user = AnonymousUser()

        mock_logout.side_effect = clear_user
        response = callback_view(request)
        mock_logout.assert_called_once()

    assert response.status_code == 302
    assert response.url == "/example-logout"


@pytest.mark.parametrize("mocked_extra_params_setting", [{"foo": 123}, {}, None])
def test_view_authentication_default(settings, mocked_extra_params_setting):
    """By default, authentication request should not trigger silent login."""
    settings.OIDC_AUTH_REQUEST_EXTRA_PARAMS = mocked_extra_params_setting

    user = factories.UserFactory()

    request = RequestFactory().request()
    request.user = user
    request.GET = {}

    view = OIDCAuthenticationRequestView()
    extra_params = view.get_extra_params(request)

    assert extra_params == (mocked_extra_params_setting or {})


@pytest.mark.parametrize("mocked_extra_params_setting", [{"foo": 123}, {}, None])
def test_view_authentication_silent_false(settings, mocked_extra_params_setting):
    """Ensure setting 'silent' parameter to a random value doesn't trigger the silent login flow."""
    settings.OIDC_AUTH_REQUEST_EXTRA_PARAMS = mocked_extra_params_setting

    user = factories.UserFactory()

    request = RequestFactory().request()
    request.user = user
    request.GET = {"silent": "foo"}

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    view = OIDCAuthenticationRequestView()
    extra_params = view.get_extra_params(request)

    assert extra_params == (mocked_extra_params_setting or {})
    assert not request.session.get("silent")


@pytest.mark.parametrize("mocked_extra_params_setting", [{"foo": 123}, {}, None])
def test_view_authentication_silent_true(settings, mocked_extra_params_setting):
    """If 'silent' parameter is set to True, the silent login should be triggered."""
    settings.OIDC_AUTH_REQUEST_EXTRA_PARAMS = mocked_extra_params_setting

    user = factories.UserFactory()

    request = RequestFactory().request()
    request.user = user
    request.GET = {"silent": "true"}

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    view = OIDCAuthenticationRequestView()
    extra_params = view.get_extra_params(request)
    expected_params = {"prompt": "none"}

    assert (
        extra_params == {**mocked_extra_params_setting, **expected_params}
        if mocked_extra_params_setting
        else expected_params
    )
    assert request.session.get("silent") is True


@mock.patch.object(
    OIDCAuthenticationCallbackView,
    "failure_url",
    new_callable=mock.PropertyMock,
    return_value="foo",
)
def test_view_callback_failure_url(mocked_failure_url):
    """Test default behavior of the 'failure_url' property."""
    user = factories.UserFactory()

    request = RequestFactory().request()
    request.user = user

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    view = OIDCAuthenticationCallbackView()
    view.request = request

    returned_url = view.failure_url

    mocked_failure_url.assert_called_once()
    assert returned_url == "foo"


@mock.patch.object(
    OIDCAuthenticationCallbackView,
    "success_url",
    new_callable=mock.PropertyMock,
    return_value="foo",
)
def test_view_callback_failure_url_silent_login(mocked_success_url):
    """If a silent login was initiated and failed, it should not be treated as a failure."""
    user = factories.UserFactory()

    request = RequestFactory().request()
    request.user = user

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    request.session["silent"] = True
    request.session.save()

    view = OIDCAuthenticationCallbackView()
    view.request = request

    returned_url = view.failure_url

    mocked_success_url.assert_called_once()
    assert returned_url == "foo"
    assert not request.session.get("silent")


def test_backchannel_missing_logout_token_returns_400():
    """POST without logout_token should return 400 with JSON and no-store header."""
    view = OIDCBackChannelLogoutView.as_view()
    url = "/oidc/backchannel-logout/"
    # No logout_token in body
    request = RequestFactory().post(url, data={})
    response = view(request)

    assert response.status_code == 400
    assert response["Cache-Control"] == "no-store"
    body = json.loads(response.content)
    assert body["error"] == "invalid_request"
    assert body["error_description"] == "Missing logout_token parameter"


@mock.patch.object(OIDCBackChannelLogoutView, "validate_logout_token", return_value=None)
@mock.patch.object(OIDCBackChannelLogoutView, "get_logout_token", return_value="token")
def test_backchannel_invalid_token_returns_400(mock_get, mock_validate):
    """Test that invalid logout token returns 400 error response."""
    view = OIDCBackChannelLogoutView.as_view()
    request = RequestFactory().post("/oidc/backchannel-logout/", data={"logout_token": "token"})
    response = view(request)

    assert response.status_code == 400
    data = json.loads(response.content)
    assert data["error"] == "invalid_request"
    assert data["error_description"] == "Invalid logout token"


@mock.patch.object(
    OIDCBackChannelLogoutView,
    "validate_logout_token",
    return_value={"events": {OIDCBackChannelLogoutView.LOGOUT_EVENT_URI: {}}, "jti": "j"},
)
@mock.patch.object(OIDCBackChannelLogoutView, "get_logout_token", return_value="token")
def test_backchannel_missing_sub_and_sid_returns_400(mock_get, mock_validate):
    """Test that logout token missing both sub and sid claims returns 400 error."""
    view = OIDCBackChannelLogoutView.as_view()
    request = RequestFactory().post("/oidc/backchannel-logout/", data={"logout_token": "token"})
    response = view(request)

    assert response.status_code == 400
    data = json.loads(response.content)
    assert data["error_description"] == "Token must contain either sub or sid claim"


@mock.patch.object(OIDCBackChannelLogoutView, "logout_user_sessions", return_value=True)
@mock.patch.object(OIDCBackChannelLogoutView, "check_and_store_jti", return_value=False)
@mock.patch.object(
    OIDCBackChannelLogoutView,
    "validate_logout_token",
    return_value={"sub": "user-sub", "events": {OIDCBackChannelLogoutView.LOGOUT_EVENT_URI: {}}, "jti": "abc"},
)
@mock.patch.object(OIDCBackChannelLogoutView, "get_logout_token", return_value="token")
def test_backchannel_jti_replay_returns_400(mock_get, mock_validate, mock_check, mock_logout_sessions):
    """Test that replayed JTI (token already processed) returns 400 error."""
    view = OIDCBackChannelLogoutView.as_view()
    request = RequestFactory().post("/oidc/backchannel-logout/", data={"logout_token": "token"})
    response = view(request)

    assert response.status_code == 400
    data = json.loads(response.content)
    assert data["error_description"] == "Token already processed"


@mock.patch.object(OIDCBackChannelLogoutView, "logout_user_sessions", return_value=True)
@mock.patch.object(OIDCBackChannelLogoutView, "check_and_store_jti", return_value=True)
@mock.patch.object(
    OIDCBackChannelLogoutView,
    "validate_logout_token",
    return_value={"sub": "user-sub", "events": {OIDCBackChannelLogoutView.LOGOUT_EVENT_URI: {}}, "jti": "abc"},
)
@mock.patch.object(OIDCBackChannelLogoutView, "get_logout_token", return_value="token")
def test_backchannel_success_returns_204_and_header(mock_get, mock_validate, mock_check, mock_logout_sessions):
    """Test successful backchannel logout returns 204 with no-store header."""
    view = OIDCBackChannelLogoutView.as_view()
    request = RequestFactory().post("/oidc/backchannel-logout/", data={"logout_token": "token"})
    response = view(request)

    assert response.status_code == 204
    assert response["Cache-Control"] == "no-store"


@mock.patch.object(OIDCBackChannelLogoutView, "logout_user_sessions", return_value=False)
@mock.patch.object(OIDCBackChannelLogoutView, "check_and_store_jti", return_value=True)
@mock.patch.object(
    OIDCBackChannelLogoutView,
    "validate_logout_token",
    return_value={"sub": "user-sub", "events": {OIDCBackChannelLogoutView.LOGOUT_EVENT_URI: {}}, "jti": "abc"},
)
@mock.patch.object(OIDCBackChannelLogoutView, "get_logout_token", return_value="token")
def test_backchannel_logout_failure_returns_400(mock_get, mock_validate, mock_check, mock_logout_sessions):
    """Test that logout failure returns 400 error response."""
    view = OIDCBackChannelLogoutView.as_view()
    request = RequestFactory().post("/oidc/backchannel-logout/", data={"logout_token": "token"})
    response = view(request)

    assert response.status_code == 400
    data = json.loads(response.content)
    assert data["error_description"] == "Logout failed"


def test_backchannel_error_response_helper():
    """Test the error_response helper method returns properly formatted error response."""
    view = OIDCBackChannelLogoutView()
    resp = view.error_response("invalid_request", "desc")
    assert resp.status_code == 400
    assert resp["Cache-Control"] == "no-store"
    assert json.loads(resp.content) == {"error": "invalid_request", "error_description": "desc"}


def test_is_valid_logout_event_true_and_false_cases():
    """Test validation of logout event structure in various scenarios."""
    view = OIDCBackChannelLogoutView()
    # Missing events
    assert not view.is_valid_logout_event({})
    # Events not a dict
    assert not view.is_valid_logout_event({"events": "x"})
    # Wrong key
    assert not view.is_valid_logout_event({"events": {"wrong": {}}})
    # Value not a dict
    assert not view.is_valid_logout_event({"events": {OIDCBackChannelLogoutView.LOGOUT_EVENT_URI: "x"}})
    # Valid
    assert view.is_valid_logout_event({"events": {OIDCBackChannelLogoutView.LOGOUT_EVENT_URI: {}}})


def test_check_and_store_jti_cache_behavior():
    """Test JTI caching behavior to prevent token replay attacks."""
    view = OIDCBackChannelLogoutView()
    assert view.check_and_store_jti("jti-1") is True
    # Replay should be rejected
    assert view.check_and_store_jti("jti-1") is False


def test_logout_user_sessions_user_not_found():
    """Test logout behavior when user with given sub is not found."""
    view = OIDCBackChannelLogoutView()
    # Non-existing sub should be treated as success per spec
    assert view.logout_user_sessions("non-existent-sub") is True


def test_logout_user_sessions_delete_all_sessions():
    """Test that all user sessions are deleted when no specific sid is provided."""
    user = factories.UserFactory()
    # Create two authenticated sessions using two clients
    client1 = APIClient()
    client1.force_login(user)
    key1 = client1.session.session_key

    client2 = APIClient()
    client2.force_login(user)
    key2 = client2.session.session_key

    view = OIDCBackChannelLogoutView()
    ok = view.logout_user_sessions(user.sub)
    assert ok is True

    # Sessions should be gone

    remaining = Session.objects.filter(session_key__in=[key1, key2])
    assert remaining.count() == 0


def test_logout_user_sessions_with_specific_sid_only_one_deleted():
    """Test that only the session with specific sid is deleted when sid is provided."""
    user = factories.UserFactory()
    # Create two authenticated sessions and set sid on each
    client_keep = APIClient()
    client_keep.force_login(user)
    session_keep = client_keep.session
    session_keep["oidc_sid"] = "keep"
    session_keep.save()
    key_keep = session_keep.session_key

    client_delete = APIClient()
    client_delete.force_login(user)
    session_delete = client_delete.session
    session_delete["oidc_sid"] = "delete"
    session_delete.save()
    key_delete = session_delete.session_key

    view = OIDCBackChannelLogoutView()
    ok = view.logout_user_sessions(user.sub, sid="delete")
    assert ok is True

    assert Session.objects.filter(session_key=key_delete).count() == 0
    assert Session.objects.filter(session_key=key_keep).count() == 1


def test_logout_user_sessions_multiple_users_same_sub_error(monkeypatch):
    """If multiple users with same sub exist, the method should return False."""
    # Create two users, and then force the query to return MultipleObjectsReturned for the same sub

    # Sanity: ORM would normally not allow duplicate subs due to unique=True, but
    # we simulate the MultipleObjectsReturned branch by monkeypatching get() to raise.
    def raise_multiple(*args, **kwargs):  # noqa: ARG001
        raise UserModel.MultipleObjectsReturned()

    monkeypatch.setattr(UserModel.objects, "get", raise_multiple)

    view = OIDCBackChannelLogoutView()
    assert view.logout_user_sessions("dup-sub") is False


@pytest.mark.django_db(transaction=True)
@responses.activate
@pytest.mark.parametrize("oidc_sid", ["sid-123", None])
def test_backchannel_full_flow_no_mock(live_server, settings, oidc_sid):
    """End-to-end backchannel logout with live JWKS and real JWT signature validation."""
    # Configure OIDC settings to point to live JWKS
    issuer = live_server.url
    settings.OIDC_RP_SIGN_ALGO = "RS256"
    settings.OIDC_OP_URL = issuer
    settings.OIDC_RP_CLIENT_ID = "test-client"
    settings.OIDC_OP_JWKS_ENDPOINT = f"{issuer}/.well-known/jwks.json"

    # Generate RSA keypair and corresponding JWK
    key = RSAKey.generate_key(private=True)
    key.ensure_kid()
    jwks = {"keys": [key.as_dict(private=False)]}

    # Mock the JWKS HTTP endpoint with responses
    responses.add(
        responses.GET,
        settings.OIDC_OP_JWKS_ENDPOINT,
        json=jwks,
        status=200,
        content_type="application/json",
    )

    # Create a user with a session and sid
    user = factories.UserFactory()
    client = APIClient()
    client.force_login(user)
    session = client.session
    session["oidc_sid"] = oidc_sid
    session.save()

    # Build logout token
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": settings.OIDC_RP_CLIENT_ID,
        "iat": now,
        "exp": now + 60,
        "jti": f"jti-{crypto.get_random_string(12)}",
        "sub": user.sub,
        "events": {OIDCBackChannelLogoutView.LOGOUT_EVENT_URI: {}},
    }
    if oidc_sid:
        payload["sid"] = oidc_sid

    token = jwt.encode(
        {"alg": "RS256", "kid": key.kid, "typ": "logout+jwt"},
        payload,
        key,
    )

    # Post backchannel logout
    url = reverse("oidc_backchannel_logout")
    resp = client.post(url, data={"logout_token": token})

    assert resp.status_code == 204
    assert resp["Cache-Control"] == "no-store"

    # Session should be deleted

    assert Session.objects.filter(session_key=session.session_key).count() == 0


def test_logout_user_sessions_sid_only_user_found():
    """Test logout behavior when only sid is provided and user is found."""
    user = factories.UserFactory()

    # Create session with oidc_sid
    client = APIClient()
    client.force_login(user)
    session = client.session
    session["oidc_sid"] = "test-sid-123"
    session.save()
    session_key = session.session_key

    view = OIDCBackChannelLogoutView()

    # Mock the user-related methods to verify they're called
    with (
        mock.patch.object(view, "revoke_refresh_tokens") as mock_revoke,
        mock.patch.object(view, "propagate_logout_to_downstream_rps") as mock_propagate,
    ):
        result = view.logout_user_sessions(sub=None, sid="test-sid-123")

        assert result is True
        # Session should be deleted
        assert Session.objects.filter(session_key=session_key).count() == 0

        # User-related methods should be called since user was resolved
        mock_revoke.assert_called_once_with(user)
        mock_propagate.assert_called_once_with(user, None, "test-sid-123")


def test_logout_user_sessions_sid_only_no_matching_session():
    """Test logout behavior when only sid is provided but no matching session found."""
    user = factories.UserFactory()

    # Create session with different oidc_sid
    client = APIClient()
    client.force_login(user)
    session = client.session
    session["oidc_sid"] = "different-sid"
    session.save()
    session_key = session.session_key

    view = OIDCBackChannelLogoutView()

    with (
        mock.patch.object(view, "revoke_refresh_tokens") as mock_revoke,
        mock.patch.object(view, "propagate_logout_to_downstream_rps") as mock_propagate,
    ):
        result = view.logout_user_sessions(sub=None, sid="test-sid-123")

        # Should succeed (per spec, already logged out is success)
        assert result is True
        # Session should still exist
        assert Session.objects.filter(session_key=session_key).count() == 1

        # User-related methods should not be called since no user was resolved
        mock_revoke.assert_not_called()
        mock_propagate.assert_not_called()


def test_logout_user_sessions_sid_only_orphaned_session():
    """Test logout behavior when only sid is provided but user no longer exists."""
    user = factories.UserFactory()

    # Create session with oidc_sid
    client = APIClient()
    client.force_login(user)
    session = client.session
    session["oidc_sid"] = "test-sid-123"
    session.save()
    session_key = session.session_key

    # Delete the user, leaving orphaned session
    user.delete()

    view = OIDCBackChannelLogoutView()

    with (
        mock.patch.object(view, "revoke_refresh_tokens") as mock_revoke,
        mock.patch.object(view, "propagate_logout_to_downstream_rps") as mock_propagate,
    ):
        result = view.logout_user_sessions(sub=None, sid="test-sid-123")

        assert result is True
        # Orphaned session should be deleted
        assert Session.objects.filter(session_key=session_key).count() == 0

        # User-related methods should not be called since user doesn't exist
        mock_revoke.assert_not_called()
        mock_propagate.assert_not_called()


def test_logout_user_sessions_sid_only_anonymous_session():
    """Test logout behavior when only sid is provided for anonymous session."""
    # Create anonymous session with oidc_sid but no _auth_user_id
    client = APIClient()
    # Force create a session without login
    session = client.session
    session.create()  # Force session creation
    session["oidc_sid"] = "test-sid-123"
    session.save()
    session_key = session.session_key

    view = OIDCBackChannelLogoutView()

    with (
        mock.patch.object(view, "revoke_refresh_tokens") as mock_revoke,
        mock.patch.object(view, "propagate_logout_to_downstream_rps") as mock_propagate,
    ):
        result = view.logout_user_sessions(sub=None, sid="test-sid-123")

        assert result is True
        # Anonymous session should be deleted
        assert Session.objects.filter(session_key=session_key).count() == 0

        # User-related methods should not be called since no user was resolved
        mock_revoke.assert_not_called()
        mock_propagate.assert_not_called()


def test_logout_user_sessions_sid_only_invalid_user_id():
    """Test logout behavior when session has invalid user_id format."""
    # Create session with invalid user_id
    client = APIClient()
    session = client.session
    session.create()  # Force session creation
    session["oidc_sid"] = "test-sid-123"
    session["_auth_user_id"] = "invalid-user-id"
    session.save()
    session_key = client.session.session_key

    view = OIDCBackChannelLogoutView()

    with (
        mock.patch.object(view, "revoke_refresh_tokens") as mock_revoke,
        mock.patch.object(view, "propagate_logout_to_downstream_rps") as mock_propagate,
    ):
        result = view.logout_user_sessions(sub=None, sid="test-sid-123")

        # Should succeed even though user_id is invalid
        assert result is True
        # Session should still exist since we continue on error
        assert Session.objects.filter(session_key=session_key).count() == 1

        # User-related methods should not be called
        mock_revoke.assert_not_called()
        mock_propagate.assert_not_called()


def test_logout_user_sessions_sid_only_multiple_sessions_only_matching_deleted():
    """Test that only the session with matching sid is deleted when multiple sessions exist."""
    user1 = factories.UserFactory()
    user2 = factories.UserFactory()

    # Create session for user1 with target sid
    client1 = APIClient()
    client1.force_login(user1)
    session1 = client1.session
    session1["oidc_sid"] = "target-sid"
    session1.save()
    key1 = session1.session_key

    # Create session for user2 with different sid
    client2 = APIClient()
    client2.force_login(user2)
    session2 = client2.session
    session2["oidc_sid"] = "other-sid"
    session2.save()
    key2 = session2.session_key

    # Create another session for user1 with different sid
    client3 = APIClient()
    client3.force_login(user1)
    session3 = client3.session
    session3["oidc_sid"] = "another-sid"
    session3.save()
    key3 = session3.session_key

    view = OIDCBackChannelLogoutView()

    with (
        mock.patch.object(view, "revoke_refresh_tokens") as mock_revoke,
        mock.patch.object(view, "propagate_logout_to_downstream_rps") as mock_propagate,
    ):
        result = view.logout_user_sessions(sub=None, sid="target-sid")

        assert result is True

        # Only the session with matching sid should be deleted
        assert Session.objects.filter(session_key=key1).count() == 0  # deleted
        assert Session.objects.filter(session_key=key2).count() == 1  # kept
        assert Session.objects.filter(session_key=key3).count() == 1  # kept

        # User-related methods should be called for user1
        mock_revoke.assert_called_once_with(user1)
        mock_propagate.assert_called_once_with(user1, None, "target-sid")


def test_logout_user_sessions_neither_sub_nor_sid():
    """Test logout behavior when neither sub nor sid is provided."""
    view = OIDCBackChannelLogoutView()

    with (
        mock.patch.object(view, "revoke_refresh_tokens") as mock_revoke,
        mock.patch.object(view, "propagate_logout_to_downstream_rps") as mock_propagate,
    ):
        result = view.logout_user_sessions(sub=None, sid=None)

        assert result is False

        # User-related methods should not be called
        mock_revoke.assert_not_called()
        mock_propagate.assert_not_called()


def test_logout_user_sessions_both_sub_and_sid_user_resolved_first():
    """Test that when both sub and sid are provided, user is resolved first (original behavior)."""
    user = factories.UserFactory()

    # Create session with oidc_sid
    client = APIClient()
    client.force_login(user)
    session = client.session
    session["oidc_sid"] = "test-sid-123"
    session.save()
    session_key = session.session_key

    view = OIDCBackChannelLogoutView()

    with (
        mock.patch.object(view, "revoke_refresh_tokens") as mock_revoke,
        mock.patch.object(view, "propagate_logout_to_downstream_rps") as mock_propagate,
    ):
        result = view.logout_user_sessions(sub=user.sub, sid="test-sid-123")

        assert result is True
        # Session should be deleted
        assert Session.objects.filter(session_key=session_key).count() == 0

        # User-related methods should be called
        mock_revoke.assert_called_once_with(user)
        mock_propagate.assert_called_once_with(user, user.sub, "test-sid-123")


def test_view_callback_silent_login_with_invalid_state():
    """Silent login failure with invalid state should raise SuspiciousOperation."""
    user = factories.UserFactory()

    request = RequestFactory().get("/callback/", data={"error": "login_required", "state": "invalid_state"})
    request.user = user

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    request.session["silent"] = True
    request.session["oidc_states"] = {"valid_state": {}}
    request.session.save()

    view = OIDCAuthenticationCallbackView()
    view.request = request

    with pytest.raises(SuspiciousOperation) as excinfo:
        view.get(request)

    assert str(excinfo.value) == "OIDC callback state validation failed during silent login"


def test_view_callback_silent_login_with_missing_state():
    """Silent login failure without state parameter should raise SuspiciousOperation."""
    user = factories.UserFactory()

    request = RequestFactory().get("/callback/", data={"error": "login_required"})
    request.user = user

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    request.session["silent"] = True
    request.session["oidc_states"] = {"valid_state": {}}
    request.session.save()

    view = OIDCAuthenticationCallbackView()
    view.request = request

    with pytest.raises(SuspiciousOperation) as excinfo:
        view.get(request)

    assert str(excinfo.value) == "OIDC callback state validation failed during silent login"


@mock.patch.object(
    OIDCAuthenticationCallbackView,
    "success_url",
    new_callable=mock.PropertyMock,
    return_value="/homepage/",
)
def test_view_callback_silent_login_with_valid_state(mocked_success_url):
    """Silent login failure with valid state should redirect and keep state for potential retry."""
    user = factories.UserFactory()

    request = RequestFactory().get("/callback/", data={"error": "login_required", "state": "valid_state"})
    request.user = user

    middleware = SessionMiddleware(get_response=lambda x: x)
    middleware.process_request(request)

    request.session["silent"] = True
    request.session["oidc_states"] = {"valid_state": {}}
    request.session.save()

    view = OIDCAuthenticationCallbackView()
    view.request = request

    response = view.get(request)

    mocked_success_url.assert_called_once()
    assert response.status_code == 302
    assert response.url == "/homepage/"
    # The silent flag should be cleaned up
    assert not request.session.get("silent")
    # CRITICAL: The state should NOT be deleted on error=login_required
    # because the SSO provider might send another callback with the actual code
    # using the same state shortly after
    assert "valid_state" in request.session.get("oidc_states", {})
