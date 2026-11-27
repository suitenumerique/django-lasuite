"""Audit declarations discovered from the test project's installed user app."""

from django.contrib.auth.models import Group

from lasuite import audit

audit.register(Group, fields=("name",), admin_values=("name",))
