"""Read the network fields and the request id behind an audit event."""

import uuid
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any

from ._django import get_setting

try:
    from dockerflow.logging import request_id_context
except ModuleNotFoundError as error:
    if error.name != "dockerflow":
        raise
    request_id_context = ContextVar("request_id", default=None)

USER_AGENT_MAX_LENGTH = 1024


def current_request_id() -> str | None:
    """Return the id of the request being served, if any."""
    return request_id_context.get(None)


def resolve_client_ip(request) -> str | None:
    """
    Return the peer address or the client address from a trusted proxy chain.

    Use the same proxy count as DRF when the project configures one.
    """
    peer = (getattr(request, "META", None) or {}).get("REMOTE_ADDR")
    num_proxies = get_setting("REST_FRAMEWORK", {}).get("NUM_PROXIES")
    if num_proxies and (forwarded := request.headers.get("X-Forwarded-For")):
        addresses = forwarded.split(",")
        return addresses[-min(num_proxies, len(addresses))].strip() or peer
    return peer


@dataclass(frozen=True)
class RequestContext:
    """
    What an audit event reads from the request behind it.

    The network fields are read once, when the request comes in. The request
    itself is kept for the actor, only known once it is authenticated: it is
    the Django request, onto which DRF copies its user and auth, but not its
    authenticator, so the auth method of a DRF view is not known from it.
    Outside a request, every field is ``None``.
    """

    request: Any = None
    request_id: str | None = None
    method: str | None = None
    path: str | None = None
    client_ip: str | None = None
    user_agent: str | None = None

    @classmethod
    def from_request(cls, request) -> "RequestContext":
        """Read the context of ``request``, its user agent cut where ECS stops."""
        meta = getattr(request, "META", None) or {}
        return cls(
            request=request,
            request_id=current_request_id(),
            method=getattr(request, "method", None),
            path=getattr(request, "path", None) or None,
            client_ip=resolve_client_ip(request),
            user_agent=meta.get("HTTP_USER_AGENT", "")[:USER_AGENT_MAX_LENGTH] or None,
        )


_request_context: ContextVar[RequestContext | None] = ContextVar("audit_request_context", default=None)


def request_context() -> RequestContext:
    """
    Return the context of the request being served, as set by ``AuditLogMiddleware``.

    It is empty outside a request.
    """
    return _request_context.get() or RequestContext()


def set_request_context(context: RequestContext) -> Token:
    """Make ``context`` the one of the request being served, until reset."""
    return _request_context.set(context)


def reset_request_context(token: Token) -> None:
    """Restore the context that was current before ``set_request_context``."""
    _request_context.reset(token)


class AuditLogMiddleware:
    """
    Settle the request id and the request context, then echo the id.

    It must come right after ``DockerflowMiddleware``, which sets the id from
    the inbound ``DOCKERFLOW_REQUEST_ID_HEADER_NAME`` header. Unless
    ``REQUEST_ID_TRUST_HEADER`` says the ingress overwrites that header, the id
    is replaced before downstream middleware and views run. Audit events and
    Dockerflow's request summary then share the generated id.

    The context of the request is kept while it is served, so that an audit
    event emitted far from the view, as from a service, still reads its actor
    and network fields from it.
    """

    def __init__(self, get_response):
        """Store the next middleware or view."""
        self.get_response = get_response

    def __call__(self, request):
        """Attach an audit context while serving the request."""
        request_id = current_request_id() if get_setting("REQUEST_ID_TRUST_HEADER", False) else None
        if not request_id:
            request_id = str(uuid.uuid4())
        request_id_context.set(request_id)

        token = set_request_context(RequestContext.from_request(request))
        try:
            response = self.get_response(request)
        finally:
            reset_request_context(token)
        header = get_setting("DOCKERFLOW_REQUEST_ID_HEADER_NAME", "X-Request-ID")
        if not response.has_header(header):
            response[header] = request_id
        return response
