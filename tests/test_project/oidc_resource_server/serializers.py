"""Simple user serializer for testing purposes."""

from django.contrib.auth import get_user_model
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    """User serializer dedicated to test the resource server."""

    class Meta:  # noqa: D106
        model = get_user_model()
        fields = ("id", "name", "email")
        read_only_fields = ("id",)
