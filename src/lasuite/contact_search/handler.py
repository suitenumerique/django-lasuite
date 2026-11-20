"""Contact search backend handler."""

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from .exceptions import ContactSearchInvalidBackendError

_UNSET = object()


class ContactSearchHandler:
    """Contact search handler managing the backends instantiation."""

    def __init__(self, backend=None):
        """
        Initialize the contact search handler.

        Args:
            backend: An optional backend definition, structured like
                ``settings.LASUITE_CONTACT_SEARCH``, used instead of the settings.

        """
        self._definition = backend
        self.reset()

    def reset(self):
        """Forget the backends built so far: the next use reads the definition again."""
        self._backend = self._definition
        self._contact_search = None
        self._fallback = _UNSET

    @property
    def backend(self):
        """Return the backend definition (``BACKEND``, ``PARAMETERS``, ``FALLBACK``)."""
        if self._backend is None:
            try:
                self._backend = settings.LASUITE_CONTACT_SEARCH.copy()
            except AttributeError as e:
                raise ImproperlyConfigured("settings.LASUITE_CONTACT_SEARCH is not configured") from e
        return self._backend

    def __call__(self):
        """Create if not existing the backend and then return it."""
        if self._contact_search is None:
            self._contact_search = self.create_contact_search(self.backend)
        return self._contact_search

    def fallback(self):
        """Return the backend answering when the main one can't, or None."""
        if self._fallback is _UNSET:
            definition = self.backend.get("FALLBACK")
            self._fallback = self.create_contact_search(definition) if definition else None
        return self._fallback

    def create_contact_search(self, params):
        """Instantiate and configure a contact search backend from its definition."""
        params = params.copy()
        backend = params.pop("BACKEND")
        parameters = params.pop("PARAMETERS", None) or {}
        try:
            klass = import_string(backend)
        except ImportError as e:
            raise ContactSearchInvalidBackendError(f"Could not find backend {backend!r}: {e}") from e
        return klass(**parameters)
