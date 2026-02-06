"""Custom Django admin site application configuration."""

from django.apps import AppConfig
from django.contrib import admin

from .sites import LaSuiteAdminSite


class LaSuiteAdminConfig(AppConfig):
    """Declare our custom Django admin site."""

    name = "lasuite.admin"
    label = "lasuite_admin"

    def ready(self):
        """Override the Django admin site class."""
        super().ready()

        admin.site.__class__ = LaSuiteAdminSite
