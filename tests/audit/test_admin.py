"""Tests for the audited Django admin site."""

import pytest
from django.contrib import admin
from django.contrib.admin.models import LogEntry
from django.contrib.auth.models import Group
from django.test import RequestFactory

from lasuite.audit.admin import AuditedAdminSite
from tests.factories import UserFactory


@pytest.mark.django_db
def test_admin_group_creation_and_deletion(audit_events):
    """The default site audits writes and preserves the target across deletion."""
    assert isinstance(admin.site, AuditedAdminSite)
    model_admin = admin.site.get_model_admin(Group)
    request = RequestFactory().post("/admin/auth/group/")
    request.user = UserFactory()
    group = Group.objects.create(name="Editors")
    group_id = str(group.pk)

    model_admin.log_addition(request, group, "Added")
    model_admin.log_deletions(request, [group])
    model_admin.delete_model(request, group)

    added, deleted = audit_events
    assert added["event"]["action"] == "admin.group.create"
    assert added["event"]["category"] == ["iam"]
    assert deleted["event"]["action"] == "admin.group.delete"
    assert deleted["entity"]["target"]["id"] == group_id
    assert not Group.objects.filter(pk=group_id).exists()
    assert LogEntry.objects.filter(object_id=group_id).count() == 2
