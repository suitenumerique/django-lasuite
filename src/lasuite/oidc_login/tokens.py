"""Access tokens stored in the session, to call resource servers as the user."""

import logging

from django.conf import settings

from lasuite.oidc_login.backends import get_oidc_refresh_token
from lasuite.oidc_login.middleware import RefreshOIDCAccessToken

logger = logging.getLogger(__name__)


def get_fresh_access_token(request):
    """
    Return the session's access token, refreshed if it expired, or None.

    Unlike the ``refresh_oidc_access_token`` decorator and the
    ``RefreshOIDCAccessToken`` middleware, a token that can't be refreshed (no
    refresh token stored, refresh refused, provider unreachable) gives None
    instead of a 401 "session expired" response. Use it where a call to a
    resource server is optional and its failure must not log the user out
    (e.g. suggestions while typing), then fall back to something else.

    Args:
        request: A Django request, or a DRF request (which forwards the
            session, the user, the path and the method this needs).

    Returns:
        str | None: The access token, None if there is no usable one.

    """
    if not getattr(settings, "OIDC_STORE_ACCESS_TOKEN", False):
        return None
    refresher = RefreshOIDCAccessToken(get_response=lambda _request: None)
    if refresher.is_expired(request):
        if not get_oidc_refresh_token(request.session):
            logger.debug("Access token expired and no refresh token stored")
            return None
        if refresher.process_request(request) is not None:
            logger.info("Access token expired and could not be refreshed")
            return None
    return request.session.get("oidc_access_token")
