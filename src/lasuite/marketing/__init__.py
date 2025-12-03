"""Marketing module."""

from django.utils.functional import LazyObject

from .handler import MarketingHandler


class DefaultMarketing(LazyObject):
    """Lazy object to handle the marketing backend."""

    def _setup(self):
        """Configure the marketing backend."""
        self._wrapped = marketing_handler()


marketing_handler = MarketingHandler()
marketing = DefaultMarketing()
