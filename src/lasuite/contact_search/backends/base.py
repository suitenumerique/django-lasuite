"""Contact search backend base module."""

from abc import ABC, abstractmethod

from . import ContactResult


class BaseContactSearchBackend(ABC):
    """Base class for all contact search backends."""

    # Whether search() needs the user's OIDC access token (stored in the
    # session at login, OIDC_STORE_ACCESS_TOKEN).
    requires_access_token = False
    # Shorter queries answer nothing.
    min_query_length = 1
    # Whether search() may return groups, and group_members() list them.
    supports_groups = False

    @abstractmethod
    def search(self, user, query: str, *, limit: int, access_token: str | None = None) -> list[ContactResult]:
        """
        Search the contacts *user* may share with.

        Args:
            user: The user searching
            query: What they typed
            limit: Maximum number of results
            access_token: The user's OIDC access token, if the backend needs it

        Returns:
            list[ContactResult]: Best first

        Raises:
            ContactSearchUnavailableError: If the backend can't answer now

        """

    def group_members(  # noqa: B027
        self, user, group_id: str, *, access_token: str | None = None
    ) -> list[ContactResult]:
        """
        List the members of a group, as users to share with.

        A backend without groups (``supports_groups = False``) has no members.

        Args:
            user: The user sharing
            group_id: The group's id at the backend
            access_token: The user's OIDC access token, if the backend needs it

        Returns:
            list[ContactResult]: The members, all of kind ``user``

        Raises:
            ContactSearchGroupNotFoundError: If the backend has no such group
            ContactSearchUnavailableError: If the backend can't answer now

        """
        return []

    def record_share(  # noqa: B027
        self, user, emails: list[str] = (), *, group_ids: list[str] = (), access_token: str | None = None
    ):
        """
        Tell the backend *user* just shared with *emails* and groups (best effort).

        Lets a backend rank these contacts higher next time. Never raises.
        Backends that don't rank contacts have nothing to do.
        """
        return
