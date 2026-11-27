"""Tests for request ID correlation and client IP resolution."""

from uuid import UUID

import pytest
from django.http import HttpResponse
from django.test import RequestFactory
from dockerflow.django.middleware import DockerflowMiddleware
from dockerflow.logging import request_id_context

from lasuite.future.logging import audit
from lasuite.future.logging.audit.request import AuditLogMiddleware, request_context, resolve_client_ip


@pytest.mark.parametrize("trust_header", [False, True])
def test_request_id_matches_response_and_summary(audit_events, settings, caplog, trust_header):
    """The same request ID reaches audit events, the response, and Dockerflow."""
    settings.REQUEST_ID_TRUST_HEADER = trust_header
    settings.DOCKERFLOW_REQUEST_ID_HEADER_NAME = "X-Trace-ID"

    def view(request):
        audit.log("document.read")
        return HttpResponse()

    middleware = DockerflowMiddleware(AuditLogMiddleware(view))
    token = request_id_context.set(None)
    try:
        with caplog.at_level("INFO", logger="request.summary"):
            response = middleware(RequestFactory().get("/documents/", HTTP_X_TRACE_ID="from-ingress"))
    finally:
        request_id_context.reset(token)

    request_id = response["X-Trace-ID"]
    if trust_header:
        assert request_id == "from-ingress"
    else:
        assert str(UUID(request_id)) == request_id
    [event] = audit_events
    assert event["http"]["request"] == {"id": request_id, "method": "GET"}
    [summary] = [record for record in caplog.records if record.name == "request.summary"]
    assert summary.rid == request_id
    assert request_context().request is None


@pytest.mark.parametrize(("num_proxies", "expected_ip"), [(None, "10.0.0.2"), (0, "10.0.0.2"), (2, "192.0.2.2")])
def test_resolve_client_ip(settings, num_proxies, expected_ip):
    """Only a configured proxy count makes forwarded addresses eligible."""
    settings.REST_FRAMEWORK = {"NUM_PROXIES": num_proxies}
    request = RequestFactory().get("/", REMOTE_ADDR="10.0.0.2", HTTP_X_FORWARDED_FOR="192.0.2.1, 192.0.2.2, 10.0.0.1")
    assert resolve_client_ip(request) == expected_ip
