"""Demo project URL configuration."""

from django.contrib import admin
from django.urls import include, path

from lasuite.oidc_login.urls import urlpatterns as oidc_urls

urlpatterns = [
    path("admin/", admin.site.urls),
    path("oidc/", include(oidc_urls)),
    path("", include("client.urls")),
]
