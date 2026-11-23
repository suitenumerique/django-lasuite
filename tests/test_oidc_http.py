"""Tests for the HTTP helper shared by the OIDC modules."""

from unittest import mock

import httpx2

from lasuite import oidc_http


def test_to_timeout_converts_requests_tuple():
    """A ``(connect, read)`` tuple applies the read value to everything but connect."""
    assert oidc_http._to_timeout((2, 7)) == httpx2.Timeout(7, connect=2)


def test_to_timeout_keeps_scalars_and_none():
    """Scalars and ``None`` have the same meaning in both clients."""
    assert oidc_http._to_timeout(5) == 5
    assert oidc_http._to_timeout(None) is None


def test_to_verify_keeps_booleans():
    """Booleans are supported as is."""
    assert oidc_http._to_verify(True) is True
    assert oidc_http._to_verify(False) is False


def test_to_verify_converts_ca_file(tmp_path):
    """A CA bundle path becomes an SSL context."""
    ca_file = tmp_path / "ca.pem"
    ca_file.touch()
    with mock.patch("lasuite.oidc_http.ssl.create_default_context") as create_context:
        assert oidc_http._to_verify(str(ca_file)) is create_context.return_value
    create_context.assert_called_once_with(cafile=str(ca_file))


def test_to_verify_converts_ca_directory(tmp_path):
    """A CA directory path becomes an SSL context."""
    with mock.patch("lasuite.oidc_http.ssl.create_default_context") as create_context:
        assert oidc_http._to_verify(str(tmp_path)) is create_context.return_value
    create_context.assert_called_once_with(capath=str(tmp_path))


def test_to_mounts_without_proxy():
    """No proxy means no mounts, so environment proxies keep working."""
    assert oidc_http._to_mounts(None, True) is None
    assert oidc_http._to_mounts({}, True) is None


def test_to_mounts_converts_requests_proxies():
    """Scheme keys become mount patterns, and transports receive ``verify``."""
    with mock.patch("lasuite.oidc_http.httpx2.HTTPTransport") as transport:
        mounts = oidc_http._to_mounts(
            {"https": "http://proxy.test:3128", "http://internal.test": "http://other.test:3128", "http": None},
            False,
        )

    assert set(mounts) == {"https://", "http://internal.test"}
    transport.assert_any_call(proxy="http://proxy.test:3128", verify=False)
    transport.assert_any_call(proxy="http://other.test:3128", verify=False)


def test_oidc_request_follows_redirects(httpx2_mock):
    """Redirects are followed, as ``requests`` did by default."""
    httpx2_mock.add_response(
        method="GET", url="https://op.test/start", status_code=302, headers={"Location": "https://op.test/end"}
    )
    httpx2_mock.add_response(method="GET", url="https://op.test/end", json={"ok": True})

    response = oidc_http.oidc_request("GET", "https://op.test/start")

    assert response.json() == {"ok": True}
    assert len(httpx2_mock.get_requests()) == 2


def test_oidc_request_through_proxy(httpx2_mock):
    """A request using a configured proxy succeeds."""
    httpx2_mock.add_response(method="GET", url="https://op.test/userinfo", json={"sub": "123"})

    response = oidc_http.oidc_request("GET", "https://op.test/userinfo", proxies={"https": "http://proxy.test:3128"})

    assert response.json() == {"sub": "123"}
