"""Healthcheck URL configuration."""

from django.urls import path

from .views import HealthcheckView

urlpatterns = [
    path("healthcheck", HealthcheckView.as_view(), name="healthcheck"),
]
