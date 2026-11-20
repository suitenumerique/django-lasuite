"""The La Suite Contacts backend: the user's contacts, matched to the application's users."""

import os

import factories
import httpx
import pytest

from lasuite.contact_search.backends.lasuite_contacts import (
    LaSuiteContactsBackend,
    card_id,
    preferred_email,
)
from lasuite.contact_search.exceptions import ContactSearchGroupNotFoundError, ContactSearchUnavailableError

from .conftest import ACCESS_TOKEN, CONTACTS_URL, INTERACTIONS_PATH, SEARCH_PATH, card

GROUP_ID = "02e230b4-4179-4da5-ac17-22c55ea5da02"
MEMBERS_PATH = f"/external_api/v1.0/groups/{GROUP_ID}/members/"


def group_card(name, email=None, members_count=3):
    """Build a group card as Contacts' search returns it."""
    found = card(name, *([email] if email else []), kind="group", uid=f"urn:uuid:{GROUP_ID}")
    found["numerique.gouv.fr:membersCount"] = members_count
    return found


pytestmark = pytest.mark.django_db


def _backend(contacts):
    return LaSuiteContactsBackend(base_url=CONTACTS_URL, transport=contacts.transport)


def _results(contacts, *cards):
    contacts.answer("GET", SEARCH_PATH, json_body={"results": list(cards)})


def test_contacts_is_asked_for_people_and_groups_with_the_users_token(user, contacts):
    """The search sends the query, the limit and the user's token."""
    _results(contacts)

    _backend(contacts).search(user, "mar", limit=5, access_token=ACCESS_TOKEN)

    request = contacts.calls[0]
    assert str(request.url).startswith(f"{CONTACTS_URL}{SEARCH_PATH}")
    assert request.headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert dict(request.url.params) == {"q": "mar", "kind": "individual,group", "limit": "5"}


def test_known_addresses_become_users_and_others_invitations(user, contacts):
    """An address of a user is that user; any other is an invitation."""
    felix = factories.UserFactory(email="felix@example.org")
    _results(
        contacts,
        card("Félix Marchand", "felix@example.org"),
        card("Marie Curie", "marie@example.org"),
    )

    results = _backend(contacts).search(user, "m", limit=5, access_token=ACCESS_TOKEN)

    assert [(result.kind, result.email, result.name, result.user) for result in results] == [
        ("user", "felix@example.org", "Félix Marchand", felix),
        ("user", "marie@example.org", "Marie Curie", None),
    ]


def test_the_order_of_contacts_is_kept(user, contacts):
    """Contacts ranks the people: their order is kept."""
    _results(contacts, *(card(f"P{i}", f"p{i}@example.org") for i in range(3)))

    results = _backend(contacts).search(user, "p", limit=5, access_token=ACCESS_TOKEN)

    assert [result.email for result in results] == [
        "p0@example.org",
        "p1@example.org",
        "p2@example.org",
    ]


def test_the_preferred_address_is_used(user, contacts):
    """The address with pref 1 is the one suggested."""
    _results(contacts, card("Bob", "bob@home.example", "bob@work.example", pref=2))

    results = _backend(contacts).search(user, "bob", limit=5, access_token=ACCESS_TOKEN)

    assert [result.email for result in results] == ["bob@work.example"]


def test_addresses_are_matched_once_normalized(user, contacts):
    """Case and spaces don't hide a user."""
    felix = factories.UserFactory(email="felix@example.org")
    _results(contacts, card("Félix", " Felix@Example.org "))

    results = _backend(contacts).search(user, "fe", limit=5, access_token=ACCESS_TOKEN)

    assert [result.user for result in results] == [felix]


def test_inactive_or_shared_addresses_are_left_out(user, contacts):
    """An inactive account or an address of several accounts can't be shared with."""
    factories.UserFactory(email="gone@example.org", is_active=False)
    factories.UserFactory(email="twice@example.org")
    factories.UserFactory(email="twice@example.org")
    _results(contacts, card("Gone", "gone@example.org"), card("Twice", "twice@example.org"))

    assert not _backend(contacts).search(user, "x", limit=5, access_token=ACCESS_TOKEN)


def test_the_user_and_cards_without_address_are_left_out(user, contacts):
    """No sharing with yourself, nor with a card without address."""
    no_email = card("No mail")
    no_email["emails"] = {}
    _results(contacts, card("Me", "Alice@example.org"), no_email, card("Bob", "bob@example.org"))

    results = _backend(contacts).search(user, "a", limit=5, access_token=ACCESS_TOKEN)

    assert [result.email for result in results] == ["bob@example.org"]


@pytest.mark.parametrize(
    "answer",
    [
        {"status": 401, "json_body": {"detail": "Invalid token"}},
        {"status": 503, "json_body": {}},
        {"status": 200, "text": "<html>not json</html>"},
        {"status": 200, "json_body": {"no": "results"}},
        {"error": httpx.ConnectTimeout("too slow")},
    ],
)
def test_contacts_failures_make_the_backend_unavailable(user, contacts, answer):
    """Any failure says the backend can't answer, so the search can fall back."""
    contacts.answer("GET", SEARCH_PATH, **answer)

    with pytest.raises(ContactSearchUnavailableError):
        _backend(contacts).search(user, "mar", limit=5, access_token=ACCESS_TOKEN)


def test_without_token_the_backend_is_unavailable(user, contacts):
    """No token, no call."""
    with pytest.raises(ContactSearchUnavailableError):
        _backend(contacts).search(user, "mar", limit=5, access_token=None)
    assert not contacts.calls


def test_one_client_is_kept_per_process(contacts):
    """The HTTP client (and its open connections) is reused between calls."""
    backend = _backend(contacts)
    client = backend.client

    assert backend.client is client


def test_a_forked_process_gets_its_own_client(contacts, monkeypatch):
    """A gunicorn worker forked after first use doesn't share the parent's sockets."""
    backend = _backend(contacts)
    parent_client = backend.client
    monkeypatch.setattr(os, "getpid", lambda: -1)

    assert backend.client is not parent_client


def test_idle_connections_expire_before_the_server_closes_them():
    """Without a test transport, idle connections are dropped after keepalive_expiry."""
    backend = LaSuiteContactsBackend(base_url=CONTACTS_URL, keepalive_expiry=30)

    pool = backend.client._transport._pool
    assert pool._keepalive_expiry == 30


def test_a_share_is_reported_as_an_interaction(user, contacts):
    """record_share posts the shared addresses, once each."""
    contacts.answer("POST", INTERACTIONS_PATH, status=204)

    _backend(contacts).record_share(
        user, ["bob@example.org", "bob@example.org", "eve@example.org"], access_token=ACCESS_TOKEN
    )

    assert contacts.calls[0].headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert contacts.bodies(INTERACTIONS_PATH) == [
        {"kind": "share", "items": [{"email": "bob@example.org"}, {"email": "eve@example.org"}]}
    ]


def test_a_large_share_is_reported_in_chunks_of_50(user, contacts):
    """Contacts takes 50 items per call with a user token."""
    contacts.answer("POST", INTERACTIONS_PATH, status=204)

    _backend(contacts).record_share(user, [f"p{i}@example.org" for i in range(120)], access_token=ACCESS_TOKEN)

    assert [len(body["items"]) for body in contacts.bodies(INTERACTIONS_PATH)] == [50, 50, 20]


def test_a_failed_report_is_ignored(user, contacts):
    """The share succeeded: a failing report doesn't raise."""
    contacts.answer("POST", INTERACTIONS_PATH, status=503)

    _backend(contacts).record_share(user, ["bob@example.org"], access_token=ACCESS_TOKEN)


def test_a_report_without_token_is_skipped(user, contacts):
    """No token, no call."""
    _backend(contacts).record_share(user, ["bob@example.org"], access_token=None)

    assert not contacts.calls


@pytest.mark.parametrize(
    ("emails", "expected"),
    [
        ({"e1": {"address": "a@x.org"}, "e2": {"address": "b@x.org", "pref": 1}}, "b@x.org"),
        ({"e1": {"address": "a@x.org"}}, "a@x.org"),
        ({}, ""),
        ({"e1": {"label": "no address"}}, ""),
    ],
)
def test_preferred_email(emails, expected):
    """The preferred address, else the first, else nothing."""
    assert preferred_email({"emails": emails}) == expected


# Groups


def test_groups_come_in_contacts_order_with_people(user, contacts):
    """A group is a result of its own, in Contacts' ranking order."""
    _results(
        contacts,
        card("Bob", "bob@example.org"),
        group_card("Conseil municipal", "conseil@example.org", members_count=8),
        card("Eve", "eve@example.org"),
    )

    results = _backend(contacts).search(user, "c", limit=5, access_token=ACCESS_TOKEN)

    assert [(result.kind, result.name) for result in results] == [
        ("user", "Bob"),
        ("group", "Conseil municipal"),
        ("user", "Eve"),
    ]
    group = results[1]
    assert (group.group_id, group.email, group.members_count, group.user) == (
        GROUP_ID,
        "conseil@example.org",
        8,
        None,
    )


def test_a_group_without_address_or_count_is_still_suggested(user, contacts):
    """Most groups have no address; an unknown count is None."""
    found = group_card("Team")
    del found["numerique.gouv.fr:membersCount"]
    _results(contacts, found)

    results = _backend(contacts).search(user, "t", limit=5, access_token=ACCESS_TOKEN)

    assert [(result.kind, result.email, result.members_count) for result in results] == [("group", "", None)]


def test_the_vendor_prefix_is_configurable(user, contacts):
    """The member count is read under Contacts' own vendor prefix."""
    found = group_card("Team")
    found["suite.example:membersCount"] = 12
    _results(contacts, found)
    backend = LaSuiteContactsBackend(base_url=CONTACTS_URL, transport=contacts.transport, vendor_prefix="suite.example")

    results = backend.search(user, "t", limit=5, access_token=ACCESS_TOKEN)

    assert results[0].members_count == 12


def _members(contacts, *pages):
    """Answer the members pages in turn."""
    answers = iter(pages)

    def next_page(request):
        contacts.calls.append(request)
        cards = next(answers)
        page = int(request.url.params["page"])
        return httpx.Response(
            200,
            json={
                "count": 0,
                "next": f"{CONTACTS_URL}{MEMBERS_PATH}?page={page + 1}" if page < len(pages) else None,
                "previous": None,
                "results": cards,
            },
        )

    return LaSuiteContactsBackend(base_url=CONTACTS_URL, transport=httpx.MockTransport(next_page))


def test_group_members_are_users_and_invitations(user, contacts):
    """Members are matched to users like search results, every page read."""
    felix = factories.UserFactory(email="felix@example.org")
    backend = _members(
        contacts,
        [card("Félix", "felix@example.org"), card("Me", "alice@example.org")],
        [card("Marie", "marie@example.org"), card("No mail")],
    )

    members = backend.group_members(user, GROUP_ID, access_token=ACCESS_TOKEN)

    assert [(member.kind, member.email, member.user) for member in members] == [
        ("user", "felix@example.org", felix),
        ("user", "marie@example.org", None),
    ]
    assert [dict(call.url.params) for call in contacts.calls] == [
        {"page": "1", "page_size": "100"},
        {"page": "2", "page_size": "100"},
    ]
    assert contacts.calls[0].headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"


def test_huge_groups_are_cut(user, contacts):
    """No more than max_group_members members are listed."""
    backend = _members(contacts, [card(f"P{i}", f"p{i}@example.org") for i in range(5)])
    backend.max_group_members = 3

    members = backend.group_members(user, GROUP_ID, access_token=ACCESS_TOKEN)

    assert len(members) == 3


def test_group_members_failures_make_the_backend_unavailable(user, contacts):
    """A failure while listing members says the backend can't answer."""
    contacts.answer("GET", MEMBERS_PATH, status=503, json_body={})

    with pytest.raises(ContactSearchUnavailableError):
        _backend(contacts).group_members(user, GROUP_ID, access_token=ACCESS_TOKEN)


def test_an_unknown_group_is_not_found(user, contacts):
    """Contacts answers 404 for a group the user can't see."""
    contacts.answer("GET", MEMBERS_PATH, status=404, json_body={})

    with pytest.raises(ContactSearchGroupNotFoundError):
        _backend(contacts).group_members(user, GROUP_ID, access_token=ACCESS_TOKEN)


def test_a_group_id_that_is_no_uuid_is_not_found(user, contacts):
    """Contacts' groups are uuids: anything else isn't asked for."""
    with pytest.raises(ContactSearchGroupNotFoundError):
        _backend(contacts).group_members(user, "not-a-uuid", access_token=ACCESS_TOKEN)
    assert not contacts.calls


def test_a_group_pick_is_reported_by_uid(user, contacts):
    """Groups are reported by their uid, people by their address."""
    contacts.answer("POST", INTERACTIONS_PATH, status=204)

    _backend(contacts).record_share(user, ["bob@example.org"], group_ids=[GROUP_ID], access_token=ACCESS_TOKEN)

    assert contacts.bodies(INTERACTIONS_PATH) == [
        {
            "kind": "share",
            "items": [{"email": "bob@example.org"}, {"uid": f"urn:uuid:{GROUP_ID}"}],
        }
    ]


@pytest.mark.parametrize(
    ("uid", "expected"),
    [(f"urn:uuid:{GROUP_ID}", GROUP_ID), (f"URN:UUID:{GROUP_ID}", GROUP_ID), (GROUP_ID, GROUP_ID)],
)
def test_card_id(uid, expected):
    """The row id in a card's uid."""
    assert card_id({"uid": uid}) == expected
