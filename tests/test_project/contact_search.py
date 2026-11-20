"""The test project's own contact search, as an application has one."""

from django.contrib.auth import get_user_model

from lasuite.contact_search.backends import USER, ContactResult
from lasuite.contact_search.backends.base import BaseContactSearchBackend


class UserEmailBackend(BaseContactSearchBackend):
    """Search the application's active users by email."""

    min_query_length = 3

    def search(self, user, query, *, limit, access_token=None):
        """Find the active users whose email contains *query*."""
        found = (
            get_user_model()
            .objects.filter(email__icontains=query, is_active=True)
            .exclude(pk=user.pk)
            .order_by("email")[:limit]
        )
        return [
            ContactResult(kind=USER, email=account.email, name=account.name or "", user=account) for account in found
        ]
