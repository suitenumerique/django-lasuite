"""Labels application configuration."""

from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class LabelsConfig(AppConfig):
    """Configure the labels application."""

    name = "lasuite.labels"
    verbose_name = _("La Suite labels")
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        """Register the system checks, which is what validates a profile at boot."""
        from . import checks  # noqa: F401, PLC0415  (import for its registration side effect)
