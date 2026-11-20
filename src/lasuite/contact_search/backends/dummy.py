"""Dummy contact search backend."""

from .base import BaseContactSearchBackend


class DummyContactSearchBackend(BaseContactSearchBackend):
    """Dummy contact search backend finding nobody."""

    def search(self, user, query, *, limit, access_token=None):
        """Find nobody."""
        return []
