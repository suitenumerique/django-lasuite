"""User model for the demo project."""

from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models


class User(AbstractBaseUser):
    """Custom user model compatible with OIDC authentication."""

    sub = models.CharField("sub", max_length=255, unique=True, null=True)
    name = models.CharField("name", max_length=255, blank=True, null=True)
    email = models.EmailField("email address", blank=True, null=True, unique=True)
    is_active = models.BooleanField("active", default=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]

    def __str__(self):
        """Return a string representation of the user."""
        return self.name or self.email or self.sub or "Unknown"
