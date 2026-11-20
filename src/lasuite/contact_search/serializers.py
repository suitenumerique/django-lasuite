"""Serializers describing the contacts a share modal suggests."""

from rest_framework import serializers


class UserContactSerializer(serializers.Serializer):
    """A user to share with."""

    kind = serializers.ChoiceField(choices=["user"])
    id = serializers.CharField(help_text="The user's id, or their email when they have no account yet.")
    email = serializers.EmailField()
    full_name = serializers.CharField(allow_blank=True)


class GroupContactSerializer(serializers.Serializer):
    """A group to share with, through its members."""

    kind = serializers.ChoiceField(choices=["group"])
    id = serializers.CharField(help_text="The group's id, to list its members.")
    name = serializers.CharField()
    email = serializers.CharField(allow_blank=True, help_text="Set for an addressable group (a shared mailbox).")
    members_count = serializers.IntegerField(allow_null=True)
