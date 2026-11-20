"""Addresses found by a backend are matched to the application's users."""

import factories
import pytest

from lasuite.contact_search.users import UserMatchingMixin, normalize_email

pytestmark = pytest.mark.django_db


class Matcher(UserMatchingMixin):
    """The mixin alone."""


def _match(user, people):
    return [(result.email, result.name, result.user) for result in Matcher().match_users(user, people).values()]


def test_known_addresses_become_users_and_others_invitations(user):
    """An address of a user is that user; any other is an invitation."""
    felix = factories.UserFactory(email="felix@example.org")

    assert _match(user, {"felix@example.org": "Félix", "marie@example.org": "Marie"}) == [
        ("felix@example.org", "Félix", felix),
        ("marie@example.org", "Marie", None),
    ]


def test_inactive_or_shared_addresses_are_left_out(user):
    """An inactive account or an address of several accounts can't be shared with."""
    factories.UserFactory(email="gone@example.org", is_active=False)
    factories.UserFactory(email="twice@example.org")
    factories.UserFactory(email="twice@example.org")

    assert _match(user, {"gone@example.org": "Gone", "twice@example.org": "Twice"}) == []


def test_the_user_and_empty_addresses_are_left_out(user):
    """No sharing with yourself, nor with no address."""
    assert _match(user, {"alice@example.org": "Me", "": "Nobody", "bob@example.org": "Bob"}) == [
        ("bob@example.org", "Bob", None)
    ]


def test_get_full_name_names_a_matched_user(user, monkeypatch):
    """When the user model has get_full_name(), it names a matched user."""
    monkeypatch.setattr(type(user), "get_full_name", lambda account: account.name, raising=False)
    felix = factories.UserFactory(email="felix@example.org", name="Félix M.")

    assert _match(user, {"felix@example.org": "Félix"}) == [("felix@example.org", "Félix M.", felix)]


def test_the_name_found_is_kept_without_get_full_name(user):
    """A user model without get_full_name() keeps the name the backend found."""
    felix = factories.UserFactory(email="felix@example.org", name="Félix M.")

    assert _match(user, {"felix@example.org": "Félix"}) == [("felix@example.org", "Félix", felix)]


def test_an_application_names_users_its_own_way(user):
    """get_user_name can be overridden for another user model."""
    felix = factories.UserFactory(email="felix@example.org", name="Félix M.")

    class NamedMatcher(UserMatchingMixin):
        def get_user_name(self, account, default=""):
            return account.name or default

    results = NamedMatcher().match_users(user, {"felix@example.org": "Félix"})

    assert [(result.name, result.user) for result in results.values()] == [("Félix M.", felix)]


@pytest.mark.parametrize(
    ("email", "expected"),
    [(" Felix@Example.ORG ", "felix@example.org"), ("ÉLODIE@x.org", "Élodie@x.org"), (None, ""), ("", "")],
)
def test_normalize_email(email, expected):
    """Addresses are stripped and their ASCII letters lowercased."""
    assert normalize_email(email) == expected
