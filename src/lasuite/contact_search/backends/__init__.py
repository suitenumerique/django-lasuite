"""Contact search backends and the result they return."""

from dataclasses import dataclass
from typing import Any

USER = "user"
GROUP = "group"


@dataclass(frozen=True)
class ContactResult:
    """
    One contact to suggest: a user or a group.

    For a ``user``: ``user`` is set when the address belongs to a user of the
    application, and sharing with them gives them access; without it, sharing
    invites ``email``.

    For a ``group``: ``group_id`` is its id at the backend, used to list its
    members; ``email`` is set for an addressable group (a shared mailbox).
    """

    kind: str
    email: str = ""
    name: str = ""
    user: Any = None
    group_id: str = ""
    members_count: int | None = None
