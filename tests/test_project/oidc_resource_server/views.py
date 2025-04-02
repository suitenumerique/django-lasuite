"""Simple viewset for testing purposes."""

from django.contrib.auth import get_user_model
from rest_framework import mixins, viewsets

from lasuite.oidc_resource_server.mixins import ResourceServerMixin

from . import serializers

User = get_user_model()


class UserViewSet(  # pylint: disable=too-many-ancestors
    ResourceServerMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    """User ViewSet dedicated to test the resource server."""

    permission_classes = []
    serializer_class = serializers.UserSerializer
    queryset = User.objects.all()
