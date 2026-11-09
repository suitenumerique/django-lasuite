"""Labels application configuration."""

from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class LabelsConfig(AppConfig):
    """Configure the labels application."""

    name = "lasuite.labels"
    verbose_name = _("La Suite labels")
    default_auto_field = "django.db.models.BigAutoField"
