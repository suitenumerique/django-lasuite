"""Smoke test for standalone audit logging with site packages disabled."""

import json
import logging
import os
from importlib.util import find_spec
from io import StringIO

from lasuite.future.logging import audit


def main():
    """Emit JSON with request and actor details using only the standard library."""
    for dependency in ("django", "rest_framework", "dockerflow"):
        assert find_spec(dependency) is None
    os.environ["AUDIT_LOG_SERVICE_NAME"] = "test-api"

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(audit.AuditJsonFormatter())
    logger = logging.getLogger(audit.AUDIT_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    for personal_data in ("false", "true"):
        os.environ["AUDIT_LOG_PERSONAL_DATA"] = personal_data
        audit.log(
            "document.read",
            request=audit.RequestContext(method="GET", path="/documents/42"),
            actor={"id": "123", "email": "user@example.org", "full_name": "Acting Account"},
            auth_method="bearer",
            target={"id": "42", "sub_type": "document"},
            user_target={
                "id": "456",
                "sub": "target-sub",
                "email": "target@example.org",
                "full_name": "Target Account",
            },
        )

    event, event_with_personal_data = map(json.loads, stream.getvalue().splitlines())
    assert event["event"]["action"] == "document.read"
    assert event["service"]["name"] == "test-api"
    assert event["http"]["request"]["method"] == "GET"
    assert event["user"] == {"id": "123", "domain": "example.org", "target": {"id": "456", "domain": "example.org"}}
    assert event["lasuite"]["actor"] == {"type": "user"}
    assert event["lasuite"]["auth"] == {"method": "bearer"}
    assert event["lasuite"]["user_target"] == {"sub": "target-sub"}
    assert event["entity"]["target"]["id"] == "42"
    assert event_with_personal_data["user"] == {
        "id": "123",
        "domain": "example.org",
        "email": "user@example.org",
        "full_name": "Acting Account",
        "target": {"id": "456", "domain": "example.org", "email": "target@example.org", "full_name": "Target Account"},
    }


if __name__ == "__main__":
    main()
