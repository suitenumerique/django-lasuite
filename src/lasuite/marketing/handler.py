"""marketing backendhandler."""

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.functional import cached_property
from django.utils.module_loading import import_string

from lasuite.marketing.exceptions import MarketingInvalidBackendError


class MarketingHandler:
    """Marketing handler managing the backend instantiation."""

    def __init__(self, backend=None):
        """Initialize the marketing handler."""
        # backend is an optional dict of marketing backend definitions
        # (structured like settings.LASUITE_MARKETING).
        self._backend = backend
        self._marketing = None

    @cached_property
    def backend(self):
        """Put in cache the backend properties from the settings."""
        if self._backend is None:
            try:
                self._backend = settings.LASUITE_MARKETING.copy()
            except AttributeError as e:
                raise ImproperlyConfigured("settings.LASUITE_MARKETING is not configured") from e
        return self._backend

    def __call__(self):
        """Create if not existing the backend and then return it."""
        if self._marketing is None:
            self._marketing = self.create_marketing(self.backend)
        return self._marketing

    def create_marketing(self, params):
        """Instantiate and configure the marketing backend."""
        params = params.copy()
        backend = params.pop("BACKEND")
        parameters = params.pop("PARAMETERS", {})
        try:
            klass = import_string(backend)
        except ImportError as e:
            raise MarketingInvalidBackendError(f"Could not find backend {backend!r}: {e}") from e
        return klass(**parameters)
