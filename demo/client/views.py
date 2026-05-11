"""Views for the resource server client demo."""

import logging

import requests
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render
from django.urls import reverse
from lasuite.oidc_login.decorators import refresh_oidc_access_token

logger = logging.getLogger(__name__)


def home(request):
    """Home page with links to authenticate and test the resource server."""
    return render(request, "client/home.html")


@login_required
def profile(request):
    """Display the current user's profile information."""
    return render(request, "client/profile.html", {"user": request.user})


@login_required
@refresh_oidc_access_token
def resource_server_me(request):
    """
    Consume the resource server /api/v1.0/users/me/ endpoint.

    This view fetches the user's access token from the session (stored during
    OIDC authentication) and uses it to make an authenticated request to the
    resource server. The response is then displayed in the template.
    """
    access_token = request.session.get("oidc_access_token")
    if not access_token:
        return HttpResponse(
            "No access token available. Please log in again.",
            status=401,
        )

    base_url = settings.RESOURCE_SERVER_BASE_URL
    if not base_url:
        return HttpResponse(
            "RESOURCE_SERVER_BASE_URL is not configured in settings.",
            status=500,
        )

    url = f"{base_url.rstrip('/')}/api/v1.0/users/me/"

    try:
        response = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
            timeout=settings.OIDC_TIMEOUT,
            verify=settings.OIDC_VERIFY_SSL,
        )
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.Timeout:
        logger.error("Request to resource server timed out")
        return HttpResponse("Request to resource server timed out.", status=504)
    except requests.exceptions.ConnectionError as exc:
        logger.error("Could not connect to resource server: %s", exc)
        return HttpResponse(
            f"Could not connect to resource server at {url}.",
            status=502,
        )
    except requests.exceptions.HTTPError as exc:
        logger.error(
            "Resource server returned HTTP error: %s - %s",
            exc.response.status_code,
            exc.response.text,
        )
        return render(
            request,
            "client/resource_server.html",
            {
                "status_code": exc.response.status_code,
                "data": exc.response.text,
                "error": True,
            },
        )
    except requests.exceptions.RequestException as exc:
        logger.error("Request to resource server failed: %s", exc)
        return HttpResponse(
            f"Request to resource server failed: {exc}",
            status=500,
        )

    return render(
        request,
        "client/resource_server.html",
        {
            "status_code": response.status_code,
            "data": data,
            "error": False,
        },
    )
