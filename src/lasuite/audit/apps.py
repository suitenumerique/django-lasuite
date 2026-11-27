"""Application configurations of the audit facility."""

from django.apps import AppConfig
from django.contrib.admin import apps as admin_apps
from django.utils.module_loading import autodiscover_modules

from .signals import connect_auth_signals


class AuditConfig(AppConfig):
    """Audit Django's authentication signals and load the project's declarations."""

    name = "lasuite.audit"
    label = "audit"

    def ready(self):
        """
        Connect the login, failed login and logout receivers.

        Then import the ``audit_registry`` module of every installed app, where
        the project registers its models and authentication classes.
        """
        connect_auth_signals()
        autodiscover_modules("audit_registry")


class AuditedAdminConfig(admin_apps.AdminConfig):
    """Serve the admin from the site that audits every write."""

    default = False
    default_site = "lasuite.audit.admin.AuditedAdminSite"
