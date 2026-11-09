"""Tests for the user creation of the Resource Server (RS) Backend."""

import contextlib

import pytest
import responses
from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation

from lasuite.oidc_resource_server import backend as backend_module
from lasuite.oidc_resource_server.backend import ResourceServerBackend
from tests.factories import UserFactory

pytestmark = pytest.mark.django_db

User = get_user_model()

USERINFO_ENDPOINT = "https://auth.server.com/userinfo"


@pytest.fixture(name="resource_server_backend")
def fixture_resource_server_backend(settings):
    """Generate a Resource Server backend allowed to create users."""
    settings.OIDC_RS_CLIENT_ID = "client_id"
    settings.OIDC_RS_CLIENT_SECRET = "client_secret"
    settings.OIDC_RS_CREATE_USER = True

    settings.OIDC_OP_URL = "https://auth.server.com"
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://auth.server.com/introspect"
    settings.OIDC_OP_USER_ENDPOINT = USERINFO_ENDPOINT
    settings.OIDC_VERIFY_SSL = True
    settings.OIDC_TIMEOUT = 10
    settings.OIDC_PROXY = None
    return ResourceServerBackend()


@responses.activate
def test_get_or_create_user_creation_disabled_by_default(resource_server_backend, settings):  # pylint: disable=unused-argument
    """Without OIDC_RS_CREATE_USER, an unknown sub is not authenticated."""
    del settings.OIDC_RS_CREATE_USER
    backend = ResourceServerBackend()

    user = backend.get_or_create_user("token", None, {"sub": "unknown-sub"})

    assert user is None
    assert User.objects.count() == 0
    assert len(responses.calls) == 0


@responses.activate
def test_get_or_create_user_creates_unknown_user(resource_server_backend):
    """An unknown sub creates the user from the userinfo endpoint."""
    responses.add(
        responses.GET,
        USERINFO_ENDPOINT,
        json={"sub": "new-sub", "email": "john@example.com", "first_name": "John", "last_name": "Doe"},
    )

    user = resource_server_backend.get_or_create_user("token", None, {"sub": "new-sub"})

    assert user.sub == "new-sub"
    assert user.email == "john@example.com"
    assert user.name == "John Doe"
    assert User.objects.count() == 1
    assert responses.calls[0].request.headers["Authorization"] == "Bearer token"


@responses.activate
def test_get_or_create_user_existing_user_skips_userinfo(resource_server_backend):
    """A known sub is returned without requesting the userinfo endpoint."""
    existing_user = UserFactory(sub="known-sub")

    user = resource_server_backend.get_or_create_user("token", None, {"sub": "known-sub"})

    assert user == existing_user
    assert len(responses.calls) == 0


@responses.activate
def test_get_or_create_user_matches_existing_user_by_email(resource_server_backend, settings):
    """An unknown sub falls back to the email matching of the creation backend."""
    settings.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = True
    existing_user = UserFactory(sub="old-sub", email="john@example.com")
    responses.add(
        responses.GET,
        USERINFO_ENDPOINT,
        json={"sub": "new-sub", "email": "john@example.com"},
    )

    user = resource_server_backend.get_or_create_user("token", None, {"sub": "new-sub"})

    assert user == existing_user
    existing_user.refresh_from_db()
    assert existing_user.sub == "new-sub"
    assert User.objects.count() == 1


@responses.activate
def test_get_or_create_user_userinfo_sub_mismatch(resource_server_backend, django_assert_num_queries):
    """A userinfo response describing another user is rejected before any write."""
    responses.add(
        responses.GET,
        USERINFO_ENDPOINT,
        json={"sub": "other-sub", "email": "john@example.com"},
    )

    # Only the lookup of the introspected sub is run.
    with (
        django_assert_num_queries(1),
        pytest.raises(SuspiciousOperation, match="User info does not match the introspected user"),
    ):
        resource_server_backend.get_or_create_user("token", None, {"sub": "new-sub"})

    assert User.objects.count() == 0


@responses.activate
def test_get_or_create_user_email_match_with_immutable_sub(resource_server_backend, settings):
    """A user matched by email that keeps its former sub is rejected and its update rolled back."""
    settings.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = True
    settings.OIDC_USER_SUB_FIELD_IMMUTABLE = True
    existing_user = UserFactory(sub="old-sub", email="john@example.com", name="Old Name")
    responses.add(
        responses.GET,
        USERINFO_ENDPOINT,
        json={"sub": "new-sub", "email": "john@example.com", "first_name": "New", "last_name": "Name"},
    )

    with pytest.raises(SuspiciousOperation, match="User info does not match the introspected user"):
        resource_server_backend.get_or_create_user("token", None, {"sub": "new-sub"})

    existing_user.refresh_from_db()
    assert existing_user.sub == "old-sub"
    assert existing_user.name == "Old Name"


def test_get_or_create_user_userinfo_outside_transaction(resource_server_backend, settings, monkeypatch, events):
    """The userinfo is fetched and checked before the transaction, and only the store step runs in it."""
    settings.OIDC_RS_USER_CREATION_BACKEND_CLASS = "tests.oidc_resource_server.test_backend_create_user.DummyBackend"
    backend = ResourceServerBackend()
    original_atomic = backend_module.transaction.atomic

    @contextlib.contextmanager
    def atomic_spy():
        events.append("atomic:start")
        with original_atomic():
            yield
        events.append("atomic:end")

    monkeypatch.setattr(backend_module.transaction, "atomic", atomic_spy)

    backend.get_or_create_user("token", None, {"sub": "new-sub"})

    assert events == [
        "get_userinfo",
        "get_claims_from_userinfo",
        "atomic:start",
        "get_or_create_user_from_claims",
        "atomic:end",
    ]


@responses.activate
def test_get_or_create_user_userinfo_error(resource_server_backend):
    """A failing userinfo endpoint is reported as a suspicious operation."""
    responses.add(responses.GET, USERINFO_ENDPOINT, status=500)

    with pytest.raises(SuspiciousOperation, match="Could not fetch user info"):
        resource_server_backend.get_or_create_user("token", None, {"sub": "new-sub"})

    assert User.objects.count() == 0


@responses.activate
def test_get_or_create_user_creation_backend_refuses(resource_server_backend, settings):
    """The creation backend may still refuse to create the user (OIDC_CREATE_USER)."""
    settings.OIDC_CREATE_USER = False
    responses.add(
        responses.GET,
        USERINFO_ENDPOINT,
        json={"sub": "new-sub", "email": "john@example.com"},
    )

    user = resource_server_backend.get_or_create_user("token", None, {"sub": "new-sub"})

    assert user is None
    assert User.objects.count() == 0


@responses.activate
def test_get_or_create_user_custom_creation_backend(resource_server_backend, settings):
    """The creation backend class is configurable."""
    settings.OIDC_RS_USER_CREATION_BACKEND_CLASS = "tests.oidc_resource_server.test_backend_create_user.DummyBackend"
    backend = ResourceServerBackend()

    user = backend.get_or_create_user("token", None, {"sub": "new-sub"})

    assert user.sub == "new-sub"
    assert user.email == "dummy@example.com"
    assert len(responses.calls) == 0


EVENTS = []


@pytest.fixture(name="events")
def fixture_events():
    """Return the list of the DummyBackend calls, emptied for each test."""
    EVENTS.clear()
    return EVENTS


class DummyBackend:
    """Creation backend building users without requesting the userinfo endpoint."""

    OIDC_USER_SUB_FIELD = "sub"

    def get_userinfo(self, access_token, id_token, payload):
        """Return a userinfo built from the introspection payload."""
        EVENTS.append("get_userinfo")
        return {"sub": payload["sub"], "email": "dummy@example.com"}

    def get_claims_from_userinfo(self, user_info):
        """Return the userinfo as claims."""
        EVENTS.append("get_claims_from_userinfo")
        return user_info

    def get_or_create_user_from_claims(self, claims):
        """Create a user from the claims."""
        EVENTS.append("get_or_create_user_from_claims")
        return User.objects.create(**claims)

    def get_or_create_user(self, access_token, id_token, payload):
        """Must not be called by the resource server."""
        raise AssertionError("get_or_create_user must not be called")
