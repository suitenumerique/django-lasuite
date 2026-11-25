"""
HTTP helper shared by the OIDC modules.

``OIDC_VERIFY_SSL``, ``OIDC_TIMEOUT`` and ``OIDC_PROXY`` are also read by
mozilla-django-oidc, which passes them to ``requests``. They must keep their
``requests`` format, so they are converted here for httpx2.
"""

import os
import ssl

import httpx2


def _to_verify(verify):
    """Convert a ``requests`` CA bundle path, which httpx2 deprecates, to an SSL context."""
    if not isinstance(verify, str):
        return verify
    if os.path.isdir(verify):
        return ssl.create_default_context(capath=verify)
    return ssl.create_default_context(cafile=verify)


def _to_timeout(timeout):
    """Convert a ``requests`` ``(connect, read)`` timeout tuple."""
    if isinstance(timeout, tuple):
        connect, read = timeout
        return httpx2.Timeout(read, connect=connect)
    return timeout


def _to_mounts(proxies, verify):
    """Convert a ``requests`` proxies dict to httpx2 transport mounts."""
    if not proxies:
        return None
    return {
        (key if "://" in key else f"{key}://"): httpx2.HTTPTransport(proxy=url, verify=verify)
        for key, url in proxies.items()
        if url
    }


def oidc_request(method, url, *, verify=True, timeout=None, proxies=None, **kwargs):  # noqa: PLR0913
    """Send a request using settings in the ``requests`` format, following redirects."""
    verify = _to_verify(verify)
    with httpx2.Client(
        verify=verify,
        timeout=_to_timeout(timeout),
        mounts=_to_mounts(proxies, verify),
        follow_redirects=True,
    ) as client:
        return client.request(method, url, **kwargs)
