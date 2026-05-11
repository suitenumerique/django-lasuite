"""Client app for the demo project."""

from django.apps import AppConfig


class ClientConfig(AppConfig):
    """Client app configuration."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "client"
    verbose_name = "Resource Server Client"
