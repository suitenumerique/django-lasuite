"""Test project URL configuration."""

from django.urls import include, path
from rest_framework.routers import DefaultRouter
from test_project.oidc_resource_server.views import UserViewSet

from lasuite.contact_search.views import ContactSearchViewSet
from lasuite.oidc_login.urls import urlpatterns as oidc_urls
from lasuite.oidc_resource_server.urls import urlpatterns as resource_server_urls

router = DefaultRouter()
router.register("users", UserViewSet, basename="users")
router.register("contacts", ContactSearchViewSet, basename="contacts")


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
