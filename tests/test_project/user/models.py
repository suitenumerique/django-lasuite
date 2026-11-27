"""User model for the application."""

import uuid

from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models


class User(AbstractBaseUser):
    """
    User model for the application.

    The primary key is a UUID, like the BaseModel of the La Suite products.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sub = models.CharField("sub", max_length=255, unique=True, null=True)  # noqa: DJ001
    issuer = models.URLField("issuer", max_length=255, blank=True, null=True)  # noqa: DJ001
    name = models.CharField("name", max_length=255, blank=True, null=True)  # noqa: DJ001
    email = models.EmailField("email address", blank=True, null=True)  # noqa: DJ001
    is_staff = models.BooleanField("staff status", default=False)
    is_active = models.BooleanField("active", default=True)
    created_at = models.DateTimeField("created at", auto_now_add=True)
    USERNAME_FIELD = "email"

    def __str__(self):
        """Return a string representation of the user."""
        return self.sub
