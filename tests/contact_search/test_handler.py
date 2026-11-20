"""The contact search handler builds the backends from settings.LASUITE_CONTACT_SEARCH."""

import pytest
from django.core.exceptions import ImproperlyConfigured

from lasuite.contact_search import contact_search, contact_search_handler
from lasuite.contact_search.backends.dummy import DummyContactSearchBackend
from lasuite.contact_search.backends.lasuite_contacts import LaSuiteContactsBackend
from lasuite.contact_search.exceptions import ContactSearchInvalidBackendError
from lasuite.contact_search.handler import ContactSearchHandler

from .conftest import CONTACTS_BACKEND, DUMMY_BACKEND


def test_the_backend_and_its_parameters_come_from_the_settings(settings):
    """BACKEND is imported and PARAMETERS passed to it."""
    settings.LASUITE_CONTACT_SEARCH = {
        "BACKEND": CONTACTS_BACKEND,
        "PARAMETERS": {"base_url": "https://contacts.example.org/", "timeout": 5},
    }

    assert isinstance(contact_search, LaSuiteContactsBackend)
    assert contact_search.base_url == "https://contacts.example.org"
    assert contact_search.timeout == 5


def test_changing_the_settings_changes_the_backend(settings):
    """The backend is read again when the settings change."""
    settings.LASUITE_CONTACT_SEARCH = {"BACKEND": CONTACTS_BACKEND, "PARAMETERS": {"base_url": "https://a.example"}}
    assert isinstance(contact_search, LaSuiteContactsBackend)

    settings.LASUITE_CONTACT_SEARCH = {"BACKEND": DUMMY_BACKEND}

    assert isinstance(contact_search, DummyContactSearchBackend)


def test_the_fallback_comes_from_the_settings(settings):
    """FALLBACK is built like the backend."""
    settings.LASUITE_CONTACT_SEARCH = {
        "BACKEND": CONTACTS_BACKEND,
        "PARAMETERS": {"base_url": "https://contacts.example.org"},
        "FALLBACK": {"BACKEND": DUMMY_BACKEND},
    }

    assert isinstance(contact_search_handler.fallback(), DummyContactSearchBackend)
    assert contact_search_handler.fallback() is contact_search_handler.fallback()


def test_no_fallback_by_default(settings):
    """Without FALLBACK, nothing answers instead of the backend."""
    settings.LASUITE_CONTACT_SEARCH = {"BACKEND": DUMMY_BACKEND}

    assert contact_search_handler.fallback() is None


def test_a_handler_takes_its_own_definition():
    """A handler can be given a definition instead of the settings."""
    assert isinstance(ContactSearchHandler({"BACKEND": DUMMY_BACKEND})(), DummyContactSearchBackend)


def test_an_unknown_backend_is_refused():
    """An unknown backend path is a configuration error."""
    with pytest.raises(ContactSearchInvalidBackendError):
        ContactSearchHandler({"BACKEND": "lasuite.contact_search.backends.nope.Nope"})()


def test_missing_settings_are_a_configuration_error(settings):
    """settings.LASUITE_CONTACT_SEARCH is required."""
    del settings.LASUITE_CONTACT_SEARCH

    with pytest.raises(ImproperlyConfigured):
        ContactSearchHandler()()
