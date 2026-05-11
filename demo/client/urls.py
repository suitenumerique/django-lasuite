"""URL configuration for the client app."""

from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("profile/", views.profile, name="profile"),
    path("resource-server/me/", views.resource_server_me, name="resource_server_me"),
]
