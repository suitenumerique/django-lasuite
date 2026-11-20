"""
Contact search: who a share modal suggests while the user types.

A contact is a user or a group. The backend is pluggable
(``settings.LASUITE_CONTACT_SEARCH``): the application's own users, or the
user's contacts in La Suite Contacts. See
documentation/how-to-use-contact-search-backend.md.
"""

from django.core.signals import setting_changed
from django.dispatch import receiver
from django.utils.functional import LazyObject, empty

from .handler import ContactSearchHandler


class DefaultContactSearch(LazyObject):
    """Lazy object to handle the contact search backend."""

    def _setup(self):
        """Configure the contact search backend."""
        self._wrapped = contact_search_handler()


contact_search_handler = ContactSearchHandler()
contact_search = DefaultContactSearch()


def reset_contact_search():
    """Forget the configured backends, so the next use reads the settings again."""
    contact_search_handler.reset()
    contact_search._wrapped = empty  # noqa: SLF001


@receiver(setting_changed)
def _reset_on_setting_changed(setting, **kwargs):
    """Read the backends again when the settings change (tests)."""
    if setting == "LASUITE_CONTACT_SEARCH":
        reset_contact_search()
