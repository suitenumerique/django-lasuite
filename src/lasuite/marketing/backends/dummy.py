"""Dummy marketing backend."""

from lasuite.marketing.backends import ContactData

from .base import BaseBackend


class DummyBackend(BaseBackend):
    """Dummy marketing backend doing nothing."""

    def create_or_update_contact(self, contact_data: ContactData, timeout: int = None) -> dict:
        """Create or update a contact."""
        return {}
