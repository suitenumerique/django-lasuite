"""Test project URL configuration."""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from lasuite.oidc_login.urls import urlpatterns as oidc_urls
from lasuite.oidc_resource_server.urls import urlpatterns as resource_server_urls
from tests.test_project.oidc_resource_server.views import UserViewSet

router = DefaultRouter()
router.register("users", UserViewSet, basename="users")


urlpatterns = [
    path(
        "",
        include(
            [
                *oidc_urls,
                *resource_server_urls,
                *router.urls,
            ]
        ),
    ),
]
