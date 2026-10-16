"""End-to-end tests of the silent login flow and the session it leaves behind."""

from importlib import import_module
from urllib.parse import parse_qs, urlparse

import pytest
import responses
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

from lasuite.oidc_login.backends import OIDCAuthenticationBackend
from tests import factories

UserModel = get_user_model()

pytestmark = pytest.mark.django_db


@pytest.fixture(
    params=["django.contrib.sessions.backends.db", "django.contrib.sessions.backends.cache"],
    ids=["db", "cache"],
)
def oidc_settings(request, settings):
    """Configure the OIDC endpoints and run each test with both session backends."""
    settings.SESSION_ENGINE = request.param
    settings.OIDC_OP_AUTHORIZATION_ENDPOINT = "http://oidc.endpoint.test/authorize"
    settings.OIDC_OP_TOKEN_ENDPOINT = "http://oidc.endpoint.test/token"
    settings.OIDC_OP_USER_ENDPOINT = "http://oidc.endpoint.test/userinfo"
    return settings


def _session_exists(settings, session_key):
    """Return whether the session record still exists in the session store."""
    return import_module(settings.SESSION_ENGINE).SessionStore().exists(session_key)


def _start_login(client, next_url, silent=True):
    """Call the authentication request view and return the state sent to the IdP."""
    data = {"next": next_url}
    if silent:
        data["silent"] = "true"
    response = client.get(reverse("oidc_authentication_init"), data=data)

    assert response.status_code == 302
    params = parse_qs(urlparse(response.url).query)
    assert (params.get("prompt") == ["none"]) is silent
    return params["state"][0]


def _login_required_callback(client, state):
    """Call the callback view as the IdP does when no SSO session exists."""
    return client.get(reverse("oidc_authentication_callback"), data={"error": "login_required", "state": state})


def _code_callback(client, settings, state, monkeypatch):
    """Call the callback view with an authorization code, mocking the IdP."""
    monkeypatch.setattr(
        OIDCAuthenticationBackend,
        "verify_token",
        lambda *args, **kwargs: {"sub": "123", "email": "test@example.com"},
    )
    responses.add(responses.POST, settings.OIDC_OP_TOKEN_ENDPOINT, json={"access_token": "token"}, status=200)
    responses.add(
        responses.GET,
        settings.OIDC_OP_USER_ENDPOINT,
        json={"sub": "123", "email": "test@example.com"},
        status=200,
    )
    return client.get(reverse("oidc_authentication_callback"), data={"code": "some-code", "state": state})


def _assert_session_cookie_deleted(settings, response):
    """Assert the response expires the session cookie."""
    cookie = response.cookies[settings.SESSION_COOKIE_NAME]
    assert cookie.value == ""
    assert cookie["max-age"] == 0


def _assert_session_cookie_kept(settings, response, session_key):
    """Assert the response leaves the session cookie untouched or refreshes it with the same key."""
    cookie = response.cookies.get(settings.SESSION_COOKIE_NAME)
    if cookie is not None:
        assert cookie.value == session_key
        assert cookie["max-age"] != 0


def test_silent_login_required_anonymous_flushes_session(oidc_settings):
    """
    An anonymous visitor without SSO session should not keep a session after a
    failed silent login: the record is deleted and the cookie removed.
    """
    client = Client()
    state = _start_login(client, "/document/")
    session_key = client.cookies[oidc_settings.SESSION_COOKIE_NAME].value
    assert _session_exists(oidc_settings, session_key)

    response = _login_required_callback(client, state)

    assert response.status_code == 302
    assert response.url == "/document/"
    assert not _session_exists(oidc_settings, session_key)
    _assert_session_cookie_deleted(oidc_settings, response)


@responses.activate
@pytest.mark.parametrize("second_callback", ["login_required", "code"])
def test_silent_login_required_with_another_pending_state(oidc_settings, monkeypatch, second_callback):
    """
    Two tabs sharing one session run a silent login at the same time: the first
    failed silent login should only consume its own state and keep the session
    so that the callback of the second tab still succeeds.
    """
    client = Client()
    first_state = _start_login(client, "/first/")
    second_state = _start_login(client, "/second/")
    session_key = client.cookies[oidc_settings.SESSION_COOKIE_NAME].value

    response = _login_required_callback(client, first_state)

    # oidc_login_next is shared by both tabs, the last request wrote it
    assert response.status_code == 302
    assert response.url == "/second/"
    _assert_session_cookie_kept(oidc_settings, response, session_key)
    session = client.session
    assert session.session_key == session_key
    assert list(session["oidc_states"]) == [second_state]
    assert session["silent"] is True
    assert session["oidc_login_next"] == "/second/"

    if second_callback == "login_required":
        response = _login_required_callback(client, second_state)

        assert response.status_code == 302
        assert response.url == "/second/"
        assert not _session_exists(oidc_settings, session_key)
        _assert_session_cookie_deleted(oidc_settings, response)
    else:
        response = _code_callback(client, oidc_settings, second_state, monkeypatch)

        assert response.status_code == 302
        assert response.url == "/second/"
        user = UserModel.objects.get(email="test@example.com")
        assert client.session["_auth_user_id"] == str(user.pk)


def test_silent_login_required_keeps_other_session_keys(oidc_settings):
    """Keys stored by the host application should survive a failed silent login."""
    client = Client()
    session = client.session
    session["foo"] = "bar"
    session.save()
    session_key = session.session_key
    client.cookies[oidc_settings.SESSION_COOKIE_NAME] = session_key

    state = _start_login(client, "/document/")
    response = _login_required_callback(client, state)

    assert response.status_code == 302
    assert response.url == "/document/"
    _assert_session_cookie_kept(oidc_settings, response, session_key)
    session = client.session
    assert session.session_key == session_key
    assert dict(session.items()) == {"foo": "bar"}


def test_silent_login_required_authenticated_keeps_session(oidc_settings):
    """The session of an authenticated user should never be flushed."""
    user = factories.UserFactory()
    client = Client()
    client.force_login(user)
    session_key = client.cookies[oidc_settings.SESSION_COOKIE_NAME].value

    state = _start_login(client, "/document/")
    response = _login_required_callback(client, state)

    assert response.status_code == 302
    assert response.url == "/document/"
    _assert_session_cookie_kept(oidc_settings, response, session_key)
    session = client.session
    assert session.session_key == session_key
    assert session["_auth_user_id"] == str(user.pk)
    for key in ("oidc_states", "silent", "oidc_login_next"):
        assert key not in session


@pytest.mark.parametrize("state", ["unknown-state", None], ids=["unknown", "missing"])
def test_silent_login_required_invalid_state(oidc_settings, state):
    """An unknown or missing state on a silent failure is still rejected with a 400."""
    client = Client(raise_request_exception=False)
    known_state = _start_login(client, "/document/")
    session_key = client.cookies[oidc_settings.SESSION_COOKIE_NAME].value

    data = {"error": "login_required"}
    if state:
        data["state"] = state
    response = client.get(reverse("oidc_authentication_callback"), data=data)

    assert response.status_code == 400
    session = client.session
    assert session.session_key == session_key
    assert list(session["oidc_states"]) == [known_state]
    assert session["silent"] is True


@responses.activate
def test_login_with_authorization_code(oidc_settings, monkeypatch):
    """Regression: a normal (non-silent) login still works end to end."""
    client = Client()
    state = _start_login(client, "/document/", silent=False)

    response = _code_callback(client, oidc_settings, state, monkeypatch)

    assert response.status_code == 302
    assert response.url == "/document/"
    user = UserModel.objects.get(email="test@example.com")
    session = client.session
    assert session["_auth_user_id"] == str(user.pk)
    assert session["oidc_states"] == {}


@pytest.mark.parametrize("error", ["interaction_required", "consent_required"])
def test_silent_login_other_error_anonymous_flushes_session(oidc_settings, error):
    """
    Other silent login errors go through failure_url: they should be cleaned up
    the same way and still redirect to the next url.
    """
    client = Client()
    state = _start_login(client, "/document/")
    session_key = client.cookies[oidc_settings.SESSION_COOKIE_NAME].value

    response = client.get(reverse("oidc_authentication_callback"), data={"error": error, "state": state})

    assert response.status_code == 302
    assert response.url == "/document/"
    assert not _session_exists(oidc_settings, session_key)
    _assert_session_cookie_deleted(oidc_settings, response)


@responses.activate
def test_silent_login_required_then_code_for_same_state(oidc_settings, monkeypatch):
    """
    A failed silent login consumes its state: a later callback carrying a code
    for the same state (e.g. a replay of the authorization url) should abort the
    login gracefully without exchanging the code.
    """
    oidc_settings.LOGIN_REDIRECT_URL_FAILURE = "/failure/"
    client = Client()
    state = _start_login(client, "/document/")

    response = _login_required_callback(client, state)

    assert response.status_code == 302
    assert response.url == "/document/"

    response = _code_callback(client, oidc_settings, state, monkeypatch)

    assert response.status_code == 302
    assert response.url == "/failure/"
    responses.assert_call_count(oidc_settings.OIDC_OP_TOKEN_ENDPOINT, 0)
    assert "_auth_user_id" not in client.session
    assert not UserModel.objects.filter(email="test@example.com").exists()
