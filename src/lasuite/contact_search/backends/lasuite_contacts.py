"""
Search the user's contacts in La Suite Contacts.

Contacts serves ranked suggestions to the other Suite apps
(``GET /external_api/v1.0/search/``, JSContact cards), lists the members of
the user's groups (``GET /external_api/v1.0/groups/{id}/members/``) and learns
from shares (``POST /external_api/v1.0/interactions/``). All are called with
the user's own OIDC access token: Contacts must accept tokens issued to the
application (its ``OIDC_RS_ALLOWED_AUDIENCES``), and the application's tokens
must name Contacts in their audience.

A share modal searches on every keystroke, so the HTTP connection to Contacts
is kept open between calls: one ``httpx.Client`` per process, reused while it
is not idle longer than ``keepalive_expiry``.
"""

import logging
import os
import threading
import uuid

import httpx

from ..exceptions import ContactSearchGroupNotFoundError, ContactSearchUnavailableError
from ..users import UserMatchingMixin
from . import GROUP, ContactResult
from .base import BaseContactSearchBackend

logger = logging.getLogger(__name__)

SEARCH_PATH = "/external_api/v1.0/search/"
INTERACTIONS_PATH = "/external_api/v1.0/interactions/"
GROUP_MEMBERS_PATH = "/external_api/v1.0/groups/{group_id}/members/"
# Contacts takes at most 50 items per interactions call with a user token.
MAX_INTERACTION_ITEMS = 50
MEMBERS_PAGE_SIZE = 100
UID_PREFIX = "urn:uuid:"


def card_id(card):
    """Return the row id in a card's uid (``urn:uuid:<id>``)."""
    uid = str(card.get("uid") or "")
    return uid[len(UID_PREFIX) :] if uid.lower().startswith(UID_PREFIX) else uid


def preferred_email(card):
    """Return the card's preferred address (``pref: 1``), else its first one."""
    emails = [
        entry for entry in (card.get("emails") or {}).values() if isinstance(entry, dict) and entry.get("address")
    ]
    if not emails:
        return ""
    emails.sort(key=lambda entry: entry.get("pref", float("inf")))
    return emails[0]["address"].strip()


class LaSuiteContactsBackend(UserMatchingMixin, BaseContactSearchBackend):
    """
    The contacts and groups of the user in La Suite Contacts, ranked by Contacts.

    People are matched to the application's users (see ``UserMatchingMixin``).

    Parameters (``LASUITE_CONTACT_SEARCH["PARAMETERS"]``):
        base_url: Contacts' address, e.g. ``https://contacts.example.org``
        timeout: Seconds to wait for Contacts (a keystroke shouldn't hang)
        verify_ssl: Check Contacts' TLS certificate
        keepalive_expiry: Seconds an idle connection is kept for reuse. Keep it
            below the idle timeout of what sits in front of Contacts (ingress,
            load balancer), so the application closes it first and never sends
            on a connection the server is closing.
        vendor_prefix: Contacts' JSCONTACT_VENDOR_PREFIX, which names the
            card properties JSContact has none for (a group's member count)
        max_group_members: Most members listed for one group
        transport: An ``httpx`` transport to use instead of the network (tests)
    """

    requires_access_token = True
    # Contacts only searches the user's own address book: short queries
    # can't be used to list the instance's users.
    min_query_length = 1
    supports_groups = True

    def __init__(  # noqa: PLR0913
        self,
        base_url,
        *,
        timeout=2,
        verify_ssl=True,
        keepalive_expiry=50,
        vendor_prefix="numerique.gouv.fr",
        max_group_members=1000,
        transport=None,
    ):
        """Configure the backend (see the class docstring for the parameters)."""
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.vendor_prefix = vendor_prefix
        self.max_group_members = max_group_members
        self._verify_ssl = verify_ssl
        self._keepalive_expiry = keepalive_expiry
        self._transport = transport
        self._client = None
        self._client_pid = None
        self._client_lock = threading.Lock()

    @property
    def client(self):
        """
        Return this process's HTTP client, created on first use.

        Created lazily and per process: a client opened before gunicorn forks
        its workers would share its sockets between them.
        """
        pid = os.getpid()
        if self._client is None or self._client_pid != pid:
            with self._client_lock:
                if self._client is None or self._client_pid != pid:
                    transport = self._transport or httpx.HTTPTransport(
                        verify=self._verify_ssl,
                        # Once more on a connection that failed to open.
                        retries=1,
                        limits=httpx.Limits(
                            max_connections=10,
                            max_keepalive_connections=5,
                            keepalive_expiry=self._keepalive_expiry,
                        ),
                    )
                    self._client = httpx.Client(base_url=self.base_url, timeout=self.timeout, transport=transport)
                    self._client_pid = pid
        return self._client

    @staticmethod
    def _headers(access_token):
        return {"Authorization": f"Bearer {access_token}"}

    def _get(self, path, access_token, params=None, *, not_found=None):
        """GET *path* from Contacts as the user and return its JSON body."""
        if not access_token:
            raise ContactSearchUnavailableError("No access token to call Contacts with.")
        try:
            response = self.client.get(path, params=params, headers=self._headers(access_token))
            if not_found is not None and response.status_code == httpx.codes.NOT_FOUND:
                raise not_found
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("Contacts call failed (%s): %s", path, exc)
            raise ContactSearchUnavailableError(str(exc)) from exc

    def _person(self, card):
        """Return ``(normalized email, name)`` of an individual card."""
        email = self.normalize_email(preferred_email(card))
        return email, (card.get("name") or {}).get("full") or ""

    def _group(self, card):
        """Return a group card as a result."""
        members_count = card.get(f"{self.vendor_prefix}:membersCount")
        return ContactResult(
            kind=GROUP,
            group_id=card_id(card),
            name=(card.get("name") or {}).get("full") or "",
            email=preferred_email(card),
            members_count=members_count if isinstance(members_count, int) else None,
        )

    def search(self, user, query, *, limit, access_token=None):
        """
        Ask Contacts for the user's contacts, then match people to users.

        Contacts' order (its ranking) is kept across people and groups.
        """
        data = self._get(SEARCH_PATH, access_token, params={"q": query, "kind": "individual,group", "limit": limit})
        try:
            cards = [card for card in data["results"] if isinstance(card, dict)]
        except (KeyError, TypeError) as exc:
            raise ContactSearchUnavailableError(f"Unexpected search answer: {exc}") from exc

        entries = []
        for card in cards:
            if card.get("kind") == GROUP:
                if card_id(card):
                    entries.append(self._group(card))
            else:
                entries.append(self._person(card))
        people = dict(entry for entry in entries if isinstance(entry, tuple))
        matched = self.match_users(user, people)
        results = []
        for entry in entries:
            if isinstance(entry, ContactResult):
                results.append(entry)
            elif (result := matched.pop(entry[0], None)) is not None:
                results.append(result)
        return results

    def group_members(self, user, group_id, *, access_token=None):
        """List the members of a group, matched to users, by name."""
        try:
            group_id = str(uuid.UUID(str(group_id)))
        except ValueError as exc:
            raise ContactSearchGroupNotFoundError(f"Not a Contacts group id: {group_id!r}") from exc
        not_found = ContactSearchGroupNotFoundError(f"No group {group_id} in the user's contacts")

        people = {}
        page = 1
        while len(people) < self.max_group_members:
            data = self._get(
                GROUP_MEMBERS_PATH.format(group_id=group_id),
                access_token,
                params={"page": page, "page_size": MEMBERS_PAGE_SIZE},
                not_found=not_found,
            )
            try:
                cards = [card for card in data["results"] if isinstance(card, dict)]
                has_next = bool(data.get("next"))
            except (KeyError, TypeError, AttributeError) as exc:
                raise ContactSearchUnavailableError(f"Unexpected members answer: {exc}") from exc
            for card in cards:
                email, name = self._person(card)
                people.setdefault(email, name)
            if not has_next:
                break
            page += 1
        people = dict(list(people.items())[: self.max_group_members])
        return list(self.match_users(user, people).values())

    def record_share(self, user, emails=(), *, group_ids=(), access_token=None):
        """Report a share to Contacts, so these contacts rank higher next time."""
        items = [{"email": email} for email in dict.fromkeys(emails) if email]
        items += [{"uid": f"{UID_PREFIX}{group_id}"} for group_id in dict.fromkeys(group_ids) if group_id]
        if not access_token or not items:
            return
        for start in range(0, len(items), MAX_INTERACTION_ITEMS):
            try:
                response = self.client.post(
                    INTERACTIONS_PATH,
                    json={"kind": "share", "items": items[start : start + MAX_INTERACTION_ITEMS]},
                    headers=self._headers(access_token),
                )
                response.raise_for_status()
            except httpx.HTTPError as exc:
                # The share itself succeeded: the ranking is a bonus.
                logger.warning("Reporting a share to Contacts failed: %s", exc)
                return
