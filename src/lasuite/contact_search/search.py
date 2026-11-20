"""Search contacts as a request's user, falling back when the backend can't answer."""

import logging

from lasuite.oidc_login.tokens import get_fresh_access_token

from . import contact_search, contact_search_handler
from .exceptions import ContactSearchUnavailableError

logger = logging.getLogger(__name__)


def get_access_token(request, backend):
    """Return the access token *backend* needs for *request*'s user, if it needs one."""
    return get_fresh_access_token(request) if backend.requires_access_token else None


def _search_with(backend, request, query, limit):
    if len(query) < backend.min_query_length:
        return []
    return backend.search(request.user, query, limit=limit, access_token=get_access_token(request, backend))


def search_contacts(request, query, *, limit):
    """
    Search the contacts *request*'s user may share with, best first.

    When the backend can't answer (down, slow, token refused or missing), the
    ``FALLBACK`` backend of ``settings.LASUITE_CONTACT_SEARCH`` answers
    instead, if any; otherwise nobody is found. Never answers "session
    expired": an expired token that can't be refreshed counts as missing.

    Args:
        request: The Django or DRF request of the user searching
        query: What they typed
        limit: Maximum number of results

    Returns:
        list[ContactResult]: The contacts found

    """
    try:
        return _search_with(contact_search, request, query, limit)
    except ContactSearchUnavailableError as exc:
        fallback = contact_search_handler.fallback()
        if fallback is None:
            logger.warning("Contact search unavailable, no fallback: %s", exc)
            return []
        logger.info("Contact search unavailable, using the fallback: %s", exc)
    try:
        return _search_with(fallback, request, query, limit)
    except ContactSearchUnavailableError as exc:
        logger.warning("Contact search fallback unavailable: %s", exc)
        return []
