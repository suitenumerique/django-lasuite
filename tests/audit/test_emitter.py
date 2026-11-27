"""Tests for ECS output, model registration, and JSON formatting."""

import json
import logging
from io import StringIO

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

from lasuite.future.logging import audit
from lasuite.future.logging.audit.actor import auth_method_for
from lasuite.future.logging.audit.testing import override_registration
from lasuite.oidc_resource_server.authentication import ResourceServerAuthentication


def test_audit_log_emits_json(settings):
    """The configured handler writes a single ECS document per event."""
    settings.AUDIT_LOG_DATA_STREAM_NAMESPACE = "test"
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(audit.AuditJsonFormatter())
    logger = logging.getLogger(audit.AUDIT_LOGGER_NAME)
    previous_level = logger.level
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        audit.log("group.update", target=Group(pk=42, name="Editors"), changed={"from": None, "to": {}})
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)

    [line] = stream.getvalue().splitlines()
    event = json.loads(line)
    assert event["event"]["action"] == "group.update"
    assert event["service"]["name"] == "test-project"
    assert event["data_stream"] == {"type": "logs", "dataset": "test_project.audit", "namespace": "test"}
    assert event["entity"]["target"] == {"id": "42", "sub_type": "group", "name": "Editors"}
    assert event["lasuite"]["actor"] == {"type": "system"}
    assert event["lasuite"]["details"] == {"changed": {"from": None, "to": {}}}


def test_override_registration_restores_invalid_override(audit_events):
    """An invalid temporary registration leaves the discovered options in place."""
    with pytest.raises(ValueError, match="invalid"), override_registration(Group, category="invalid"):
        pytest.fail("The invalid registration should have raised")
    audit.log("group.update", target=Group(pk=42, name="Editors"))

    [event] = audit_events
    assert event["entity"]["target"]["name"] == "Editors"


@pytest.mark.parametrize("sub", ["target-sub", None])
def test_user_target_subject(audit_events, sub):
    """Include the resolved target account's subject when available."""
    target = get_user_model()(sub=sub, email="target@example.org")
    audit.log("user.update", target=target, actor={"id": "actor", "sub": "actor-sub"})

    [event] = audit_events
    assert event["user"]["target"]["id"] == str(target.pk)
    assert event["lasuite"]["actor"]["sub"] == "actor-sub"
    if sub is None:
        assert "user_target" not in event["lasuite"]
    else:
        assert event["lasuite"]["user_target"] == {"sub": sub}


@pytest.mark.parametrize("personal_data", [None, False, True])
def test_account_personal_data_requires_opt_in(audit_events, settings, monkeypatch, personal_data):
    """The setting controls email and full name for the actor and account affected."""
    monkeypatch.delenv("AUDIT_LOG_PERSONAL_DATA", raising=False)
    if personal_data is not None:
        settings.AUDIT_LOG_PERSONAL_DATA = personal_data
    if personal_data is False:
        monkeypatch.setenv("AUDIT_LOG_PERSONAL_DATA", "true")

    user_model = get_user_model()
    monkeypatch.setattr(user_model, "get_full_name", lambda user: user.name, raising=False)
    actor = user_model(email="actor@example.org")
    actor.full_name = "Acting Account"
    target = user_model(email="target@example.org", name="Target Account")

    audit.log("user.update", actor=actor, user_target=target)

    [event] = audit_events
    user_fields = {"id": str(actor.pk), "domain": "example.org"}
    target_fields = {"id": str(target.pk), "domain": "example.org"}
    if personal_data:
        user_fields.update(email=actor.email, full_name=actor.full_name)
        target_fields.update(email=target.email, full_name=target.name)
    assert event["user"] == {**user_fields, "target": target_fields}


def test_resource_server_authentication_is_named():
    """LaSuite's DRF resource server authenticator has a built-in label."""
    authenticator = object.__new__(ResourceServerAuthentication)
    assert auth_method_for(authenticator) == "resource_server"
