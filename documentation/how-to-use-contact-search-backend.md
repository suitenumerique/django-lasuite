# Using the contact search backend

A share modal suggests people as the user types a name or an email. This
module answers it with a pluggable backend: the application's own users, or
the user's contacts and groups in [La Suite Contacts](https://github.com/suitenumerique/contacts),
ranked by how often the user shares with them.

A contact is a **user** or a **group**. An application without groups of its
own shares with a group through its members.

## Installation

```bash
pip install "django-lasuite[contact-search]"
```

It brings `drf` and `oidc-login`: the backend calling Contacts uses the user's
OIDC access token, and the API is a Django REST framework viewset.

## Configuration

`settings.LASUITE_CONTACT_SEARCH` names the backend, its parameters and,
optionally, a fallback answering when the backend can't (service down, token
refused or missing):

```python
LASUITE_CONTACT_SEARCH = {
    "BACKEND": "lasuite.contact_search.backends.lasuite_contacts.LaSuiteContactsBackend",
    "PARAMETERS": {"base_url": "https://contacts.example.org", "timeout": 2},
    # Optional: the application's own search, when Contacts can't answer.
    "FALLBACK": {
        "BACKEND": "myapp.contact_search.LocalContactSearchBackend",
        "PARAMETERS": {},
    },
}
```

Changing the setting (e.g. with pytest-django's `settings` fixture) builds the
backends again.

### Backends

| Backend | Suggests |
|---|---|
| `lasuite.contact_search.backends.dummy.DummyContactSearchBackend` | Nobody |
| `lasuite.contact_search.backends.lasuite_contacts.LaSuiteContactsBackend` | The user's contacts and groups in La Suite Contacts |

Most applications write their own backend for their users (who may be
suggested, on which fields, from how many characters) and use it as the
`BACKEND`, or as the `FALLBACK` of the La Suite Contacts backend.

### Writing a backend

Inherit `lasuite.contact_search.backends.base.BaseContactSearchBackend` and
return `lasuite.contact_search.backends.ContactResult` objects:

```python
from lasuite.contact_search.backends import USER, ContactResult
from lasuite.contact_search.backends.base import BaseContactSearchBackend


class LocalContactSearchBackend(BaseContactSearchBackend):
    min_query_length = 5  # shorter queries find nobody

    def search(self, user, query, *, limit, access_token=None):
        found = User.objects.filter(email__icontains=query, is_active=True)[:limit]
        return [ContactResult(kind=USER, email=u.email, name=u.full_name, user=u) for u in found]
```

- `search(user, query, *, limit, access_token=None)`: best first. A result of
  kind `user` with `user` set is an account (sharing gives it access); without
  `user`, sharing invites `email`. Raise `ContactSearchUnavailableError` when
  the backend can't answer, so the fallback does.
- `requires_access_token`: `True` to receive the user's OIDC access token.
- `min_query_length`: shorter queries find nobody, without calling `search`.
- `supports_groups` and `group_members(user, group_id, *, access_token=None)`:
  for backends with groups. Raise `ContactSearchGroupNotFoundError` for an
  unknown group.
- `record_share(user, emails, *, group_ids, access_token=None)`: told about
  shares (best effort, never raises), to rank contacts.

## The La Suite Contacts backend

It calls Contacts' external API with the user's own access token:
`GET /external_api/v1.0/search/`, `GET /external_api/v1.0/groups/{id}/members/`
and `POST /external_api/v1.0/interactions/` (kind `share`).

| Parameter | Default | |
|---|---|---|
| `base_url` | (required) | Contacts' address |
| `timeout` | `2` | Seconds to wait for Contacts |
| `verify_ssl` | `True` | Check Contacts' TLS certificate |
| `keepalive_expiry` | `50` | Seconds an idle connection is kept open for reuse (see below) |
| `vendor_prefix` | `numerique.gouv.fr` | Contacts' `JSCONTACT_VENDOR_PREFIX`, which names a group's member count in its cards |
| `max_group_members` | `1000` | Most members listed for one group |

### Matching people to users

Each address Contacts returns is matched to the application's users
(`UserMatchingMixin`):

- an address of exactly one active user becomes that user;
- an address no account uses becomes an invitation;
- an address of an inactive user, or of several users, is left out, and so is
  the user's own address.

Addresses are compared exactly, once stripped and their ASCII letters
lowercased, with the user model's `EMAIL_FIELD`, so the database index serves
the query. A matched user is named by the model's `get_full_name()` if it has
one, else by the name in Contacts. Subclass the backend to change any step
(`normalize_email`, `get_users_by_email`, `can_share_with`, `get_user_name`):

```python
class AppContactsBackend(LaSuiteContactsBackend):
    def get_user_name(self, account, default=""):
        return account.full_name or default
```

### One connection, kept open

A share modal searches on every keystroke. The backend keeps its HTTP
connection to Contacts open between calls (one `httpx` client per process,
created after gunicorn forks its workers), so a keystroke doesn't pay for a
new TCP and TLS handshake.

- Each worker of each pod has its own connections (5 kept open at most).
- A connection idle longer than `keepalive_expiry` is closed by the
  application. Keep it below the idle timeout of what sits in front of
  Contacts (ingress, load balancer; often 60 s), otherwise the application
  may send on a connection the server is closing. A request that fails to
  connect is retried once.
- Inside a cluster, prefer Contacts' internal service address as `base_url`:
  no TLS, no ingress, and no ingress idle timeout to stay under.

### Contacts and the identity provider

- The application's access tokens must name Contacts in their audience (in
  Keycloak, an audience mapper on the application's client), and Contacts
  must accept tokens issued to the application (its
  `OIDC_RS_ALLOWED_AUDIENCES`) and the `share` interactions it reports.
- The application must store the tokens in the session at login:
  `OIDC_STORE_ACCESS_TOKEN = True`, `OIDC_STORE_REFRESH_TOKEN = True` and
  `OIDC_STORE_REFRESH_TOKEN_KEY` (see
  [how-to-use-oidc-call-to-resource-server.md](how-to-use-oidc-call-to-resource-server.md)).
  An expired token is refreshed; one that can't be refreshed makes the search
  fall back, it never logs the user out.

## The API

Register the viewset in the application's router, usually through a subclass
setting the throttles:

```python
from lasuite.contact_search.views import ContactSearchViewSet


class ContactViewSet(ContactSearchViewSet):
    throttle_classes = [...]
    search_limit = 10

    def filter_results(self, results):
        # e.g. leave out the users who already have access to an item
        return results


router.register("contacts", ContactViewSet, basename="contacts")
```

`GET /contacts/?q=<query>` answers the contacts, best first:

```json
[
  {"kind": "user", "id": "<user id>", "email": "felix@example.org", "full_name": "Félix Marchand"},
  {"kind": "user", "id": "marie@example.org", "email": "marie@example.org", "full_name": "Marie Curie"},
  {"kind": "group", "id": "<group id>", "name": "Conseil municipal", "email": "", "members_count": 8}
]
```

- A user without an account has their email as `id`: sharing with them is an
  invitation (the convention of `@gouvfr-lasuite/ui-components`' share modal).
- `GET /contacts/groups/<id>/members/` answers a group's members, as users. A
  frontend shares with each of them in place of the group. Listing them
  reports the group as picked, so it ranks higher next time. `404` for an
  unknown group or a backend without groups, `503` when the backend can't
  answer.

Override `serialize_user` / `serialize_group` to add fields, and
`get_search_limit` to compute the number of results. The serializers in
`lasuite.contact_search.serializers` describe both shapes, e.g. for a
drf-spectacular `PolymorphicProxySerializer` on `kind`.

## Reporting shares

Call `report_share` where the application creates accesses or invitations, so
the backend ranks these people higher next time:

```python
from lasuite.contact_search.sharing import report_share

report_share(request, [invitation.email])
```

It runs once the transaction is committed, and never fails the share.

## Searching from Python

`lasuite.contact_search.search.search_contacts(request, query, *, limit)` is
what the viewset calls: the backend with the user's fresh access token, then
the fallback if it can't answer.
