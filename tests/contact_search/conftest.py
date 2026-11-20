"""Fixtures for the contact search tests."""

import json
import time

import factories
import httpx
import pytest
from rest_framework.test import APIClient

CONTACTS_URL = "https://contacts.example.org"
SEARCH_PATH = "/external_api/v1.0/search/"
INTERACTIONS_PATH = "/external_api/v1.0/interactions/"
ACCESS_TOKEN = "user-access-token"
CONTACTS_BACKEND = "lasuite.contact_search.backends.lasuite_contacts.LaSuiteContactsBackend"
DUMMY_BACKEND = "lasuite.contact_search.backends.dummy.DummyContactSearchBackend"


class FakeContacts:
    """La Suite Contacts, as an httpx transport recording what it receives."""

    def __init__(self):
        """Start with no call and no answer."""
        self.calls = []
        self._answers = {}

    def answer(self, method, path, **response):
        """
        Set how to answer *method* *path* from now on.

        *response* takes ``json_body``, ``status`` (200), ``text`` or ``error``
        (an exception to raise instead of answering).
        """
        self._answers[(method, path)] = (
            response.get("json_body"),
            response.get("status", 200),
            response.get("text"),
            response.get("error"),
        )

    def handle(self, request):
        """Answer a request."""
        self.calls.append(request)
        answer = self._answers.get((request.method, request.url.path))
        if answer is None:
            raise httpx.ConnectError("Contacts is not reachable", request=request)
        json_body, status, text, error = answer
        if error is not None:
            raise error
        if text is not None:
            return httpx.Response(status, text=text)
        return httpx.Response(status, json=json_body)

    @property
    def transport(self):
        """Return the transport to give the backend."""
        return httpx.MockTransport(self.handle)

    def bodies(self, path):
        """Return the JSON bodies sent to *path*."""
        return [json.loads(call.content) for call in self.calls if call.url.path == path]


@pytest.fixture(name="contacts")
def contacts_fixture():
    """Return a fake La Suite Contacts."""
    return FakeContacts()


@pytest.fixture(name="oidc_settings")
def oidc_settings_fixture(settings):
    """Store the user's access token in the session at login."""
    settings.OIDC_STORE_ACCESS_TOKEN = True
    settings.OIDC_OP_TOKEN_ENDPOINT = "https://auth.example.com/token"
    settings.OIDC_OP_AUTHORIZATION_ENDPOINT = "https://auth.example.com/authorize"
    settings.OIDC_AUTHENTICATION_CALLBACK_URL = "oidc_authentication_callback"
    return settings


@pytest.fixture(name="contacts_backend")
def contacts_backend_fixture(oidc_settings, contacts):
    """Configure the La Suite Contacts backend, talking to the fake Contacts, with no fallback."""
    oidc_settings.LASUITE_CONTACT_SEARCH = {
        "BACKEND": CONTACTS_BACKEND,
        "PARAMETERS": {"base_url": CONTACTS_URL, "transport": contacts.transport},
    }
    return contacts


def card(name, *emails, pref=None, kind="individual", uid=None):
    """Build a JSContact card as Contacts' search returns it."""
    entries = {}
    for index, address in enumerate(emails, start=1):
        entry = {"address": address}
        if pref == index or (pref is None and index == 1):
            entry["pref"] = 1
        entries[f"e{index}"] = entry
    return {
        "@type": "Card",
        "version": "1.0",
        "uid": uid or f"urn:uuid:{name}",
        "kind": kind,
        "name": {"full": name},
        "emails": entries,
    }


def logged_in_client(user, *, access_token=ACCESS_TOKEN, expires_in=3600):
    """Build a client logged in as *user* through OIDC, with an access token in its session."""
    client = APIClient()
    # Logged in through OIDC, like real users: only those sessions refresh.
    client.force_login(user, backend="lasuite.oidc_login.backends.OIDCAuthenticationBackend")
    session = client.session
    if access_token:
        session["oidc_access_token"] = access_token
    session["oidc_id_token_expiration"] = time.time() + expires_in
    session.save()
    return client


@pytest.fixture(name="user")
def user_fixture(db):
    """Return the user searching."""
    return factories.UserFactory(email="alice@example.org")
