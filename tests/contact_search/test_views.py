"""The API a share modal calls: GET /contacts/?q= and GET /contacts/groups/<id>/members/."""

import factories
import httpx
import pytest
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from lasuite.contact_search.views import ContactSearchViewSet

from .conftest import (
    ACCESS_TOKEN,
    INTERACTIONS_PATH,
    SEARCH_PATH,
    card,
    logged_in_client,
)

pytestmark = pytest.mark.django_db

LOCAL_BACKEND = "test_project.contact_search.UserEmailBackend"
GROUP_ID = "02e230b4-4179-4da5-ac17-22c55ea5da02"
MEMBERS_PATH = f"/external_api/v1.0/groups/{GROUP_ID}/members/"


@pytest.fixture(name="with_fallback")
def with_fallback_fixture(contacts_backend, settings):
    """Fall back to the application's own users when Contacts can't answer."""
    settings.LASUITE_CONTACT_SEARCH = {
        **settings.LASUITE_CONTACT_SEARCH,
        "FALLBACK": {"BACKEND": LOCAL_BACKEND},
    }
    return contacts_backend


def _search(client, query):
    response = client.get("/contacts/", {"q": query})
    assert response.status_code == 200
    return response.json()


def test_anonymous_users_are_refused():
    """Only for logged-in users."""
    assert APIClient().get("/contacts/", {"q": "bob"}).status_code in (401, 403)


def test_the_dummy_backend_finds_nobody(user):
    """The test project's default backend."""
    assert _search(logged_in_client(user), "bob") == []


def test_contacts_come_back_as_users_and_invitations(user, contacts_backend):
    """Users keep their id; other addresses use their email as id."""
    felix = factories.UserFactory(email="felix@example.org")
    contacts_backend.answer(
        "GET",
        SEARCH_PATH,
        json_body={"results": [card("Félix", "felix@example.org"), card("Marie", "marie@example.org")]},
    )

    assert _search(logged_in_client(user), "m") == [
        {"kind": "user", "id": str(felix.pk), "email": "felix@example.org", "full_name": "Félix"},
        {"kind": "user", "id": "marie@example.org", "email": "marie@example.org", "full_name": "Marie"},
    ]
    assert contacts_backend.calls[0].headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"


def test_an_empty_query_answers_nothing(user, contacts_backend):
    """No query, no call."""
    assert _search(logged_in_client(user), "") == []
    assert not contacts_backend.calls


def test_contacts_down_falls_back(user, with_fallback):
    """When Contacts fails, the fallback backend answers."""
    bob = factories.UserFactory(email="bob@example.org")
    with_fallback.answer("GET", SEARCH_PATH, error=httpx.ConnectTimeout("down"))

    assert [result["id"] for result in _search(logged_in_client(user), "bob")] == [str(bob.pk)]


def test_the_fallback_keeps_its_own_query_rules(user, with_fallback):
    """A query too short for the fallback finds nobody."""
    factories.UserFactory(email="bob@example.org")

    assert _search(logged_in_client(user), "bo") == []


def test_without_fallback_contacts_down_answers_nothing(user, contacts_backend):
    """No fallback configured: an outage finds nobody."""
    factories.UserFactory(email="bob@example.org")
    contacts_backend.answer("GET", SEARCH_PATH, status=503, json_body={})

    assert _search(logged_in_client(user), "bob") == []


def test_without_token_in_session_it_falls_back(user, with_fallback):
    """No stored token: the fallback answers and Contacts isn't called."""
    bob = factories.UserFactory(email="bob@example.org")

    results = _search(logged_in_client(user, access_token=None), "bob")

    assert [result["id"] for result in results] == [str(bob.pk)]
    assert not with_fallback.calls


def test_an_expired_token_without_refresh_token_falls_back(user, with_fallback):
    """An expired token that can't be refreshed doesn't log the user out."""
    bob = factories.UserFactory(email="bob@example.org")

    response = logged_in_client(user, expires_in=-60).get("/contacts/", {"q": "bob"})

    assert response.status_code == 200
    assert [result["id"] for result in response.json()] == [str(bob.pk)]
    assert not with_fallback.calls


def test_groups_are_suggested_with_their_member_count(user, contacts_backend):
    """A group comes back with its own shape."""
    group = card("Conseil", "conseil@example.org", kind="group", uid=f"urn:uuid:{GROUP_ID}")
    group["numerique.gouv.fr:membersCount"] = 8
    contacts_backend.answer("GET", SEARCH_PATH, json_body={"results": [group]})

    assert _search(logged_in_client(user), "con") == [
        {"kind": "group", "id": GROUP_ID, "name": "Conseil", "email": "conseil@example.org", "members_count": 8}
    ]


def test_group_members_are_listed_and_the_group_reported(user, contacts_backend, django_capture_on_commit_callbacks):
    """Listing members for a share reports the group as picked."""
    felix = factories.UserFactory(email="felix@example.org")
    contacts_backend.answer(
        "GET",
        MEMBERS_PATH,
        json_body={"next": None, "results": [card("Félix", "felix@example.org"), card("Marie", "marie@example.org")]},
    )
    contacts_backend.answer("POST", INTERACTIONS_PATH, status=204)

    with django_capture_on_commit_callbacks(execute=True):
        response = logged_in_client(user).get(f"/contacts/groups/{GROUP_ID}/members/")

    assert response.status_code == 200
    assert response.json() == [
        {"kind": "user", "id": str(felix.pk), "email": "felix@example.org", "full_name": "Félix"},
        {"kind": "user", "id": "marie@example.org", "email": "marie@example.org", "full_name": "Marie"},
    ]
    assert contacts_backend.bodies(INTERACTIONS_PATH) == [{"kind": "share", "items": [{"uid": f"urn:uuid:{GROUP_ID}"}]}]


def test_a_backend_without_groups_has_none_to_list(user):
    """The dummy backend has no groups."""
    assert logged_in_client(user).get(f"/contacts/groups/{GROUP_ID}/members/").status_code == 404


@pytest.mark.parametrize("group_id", ["not-a-uuid", "02e230b4"])
def test_a_group_unknown_to_the_backend_is_not_found(user, contacts_backend, group_id):
    """The backend decides what a group id is."""
    response = logged_in_client(user).get(f"/contacts/groups/{group_id}/members/")

    assert response.status_code == 404
    assert not contacts_backend.calls


def test_members_unavailable_answers_503(user, contacts_backend):
    """No fallback for a group: the share modal tells the user to retry."""
    contacts_backend.answer("GET", MEMBERS_PATH, status=500, json_body={})
    client = logged_in_client(user)
    client.raise_request_exception = False

    response = client.get(f"/contacts/groups/{GROUP_ID}/members/")

    assert response.status_code == 503
    assert response.json()["detail"] == "The group's members can't be listed now. Try again later."


def test_anonymous_users_cant_list_members():
    """Only for logged-in users."""
    assert APIClient().get(f"/contacts/groups/{GROUP_ID}/members/").status_code in (401, 403)


def test_a_subclass_can_filter_and_extend_results(user, contacts_backend):
    """Applications customize the viewset by subclassing it."""

    class AppViewSet(ContactSearchViewSet):
        search_limit = 3

        def filter_results(self, results):
            return [result for result in results if result.email != "hidden@example.org"]

        def serialize_user(self, result):
            return {**super().serialize_user(result), "short_name": result.name.split()[0]}

    contacts_backend.answer(
        "GET",
        SEARCH_PATH,
        json_body={"results": [card("Hidden One", "hidden@example.org"), card("Marie Curie", "marie@example.org")]},
    )
    api_request = APIRequestFactory().get("/contacts/", {"q": "m"})
    force_authenticate(api_request, user=user)
    # The session of an OIDC login, holding the access token.
    api_request.session = logged_in_client(user).session
    response = AppViewSet.as_view({"get": "list"})(api_request)

    assert response.data == [
        {
            "kind": "user",
            "id": "marie@example.org",
            "email": "marie@example.org",
            "full_name": "Marie Curie",
            "short_name": "Marie",
        }
    ]
    assert contacts_backend.calls[0].url.params["limit"] == "3"
