"""User model for the application."""

from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models


class User(AbstractBaseUser):
    """User model for the application."""

    sub = models.CharField("sub", max_length=255, unique=True, null=True)  # noqa: DJ001
    name = models.CharField("name", max_length=255, blank=True, null=True)  # noqa: DJ001
    email = models.EmailField("email address", blank=True, null=True)  # noqa: DJ001
    is_active = models.BooleanField("active", default=True)
    USERNAME_FIELD = "email"

    def __str__(self):
        """Return a string representation of the user."""
        return self.sub
