"""report_share tells the backend about shares, after they are committed."""

from unittest.mock import MagicMock

import pytest
from django.test import RequestFactory

from lasuite.contact_search.backends.dummy import DummyContactSearchBackend
from lasuite.contact_search.sharing import report_share

from .conftest import ACCESS_TOKEN, DUMMY_BACKEND, INTERACTIONS_PATH

pytestmark = pytest.mark.django_db


def _request(user, access_token=ACCESS_TOKEN):
    request = RequestFactory().post("/share")
    request.user = user
    request.session = {"oidc_access_token": access_token} if access_token else {}
    return request


def test_a_share_is_reported_once_committed(user, contacts_backend, django_capture_on_commit_callbacks):
    """People and groups are reported together, after the commit."""
    contacts_backend.answer("POST", INTERACTIONS_PATH, status=204)

    with django_capture_on_commit_callbacks() as callbacks:
        report_share(_request(user), ["bob@example.org", ""], group_ids=["g1"])
    assert not contacts_backend.calls
    for callback in callbacks:
        callback()

    assert contacts_backend.calls[0].headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert contacts_backend.bodies(INTERACTIONS_PATH) == [
        {"kind": "share", "items": [{"email": "bob@example.org"}, {"uid": "urn:uuid:g1"}]}
    ]


def test_nothing_to_report(user, contacts_backend, django_capture_on_commit_callbacks):
    """No address and no group: nothing is scheduled."""
    with django_capture_on_commit_callbacks() as callbacks:
        report_share(_request(user), ["", None])

    assert not callbacks


def test_no_token_in_session_skips_a_backend_that_needs_one(user, contacts_backend, django_capture_on_commit_callbacks):
    """A request without the user's token (another app's call) reports nothing."""
    with django_capture_on_commit_callbacks() as callbacks:
        report_share(_request(user, access_token=None), ["bob@example.org"])

    assert not callbacks


def test_a_backend_without_token_is_told_too(user, settings, django_capture_on_commit_callbacks, monkeypatch):
    """A backend that needs no token is told even without one."""
    settings.LASUITE_CONTACT_SEARCH = {"BACKEND": DUMMY_BACKEND}
    record_share = MagicMock()
    monkeypatch.setattr(DummyContactSearchBackend, "record_share", record_share)

    with django_capture_on_commit_callbacks(execute=True):
        report_share(_request(user, access_token=None), ["bob@example.org"])

    record_share.assert_called_once_with(user, ["bob@example.org"], group_ids=[], access_token=None)


def test_a_failed_report_is_ignored(user, contacts_backend, django_capture_on_commit_callbacks):
    """The share is saved even when the backend fails."""
    contacts_backend.answer("POST", INTERACTIONS_PATH, status=503)

    with django_capture_on_commit_callbacks(execute=True):
        report_share(_request(user), ["bob@example.org"])

    assert len(contacts_backend.calls) == 1
