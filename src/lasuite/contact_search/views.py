"""API a share modal calls to suggest contacts and expand groups."""

from rest_framework import exceptions, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from . import contact_search
from .backends import GROUP
from .exceptions import ContactSearchGroupNotFoundError, ContactSearchUnavailableError
from .search import get_access_token, search_contacts
from .sharing import report_share


class GroupMembersUnavailable(exceptions.APIException):
    """The contact search backend can't list a group's members now."""

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "The group's members can't be listed now. Try again later."
    default_code = "group_members_unavailable"


class ContactSearchViewSet(viewsets.ViewSet):
    """
    Contacts to share with, as a share modal suggests them while the user types.

    - ``GET <prefix>/?q=``: people and groups, best first. Each result has a
      ``kind``: ``user`` or ``group``. A user without an account comes back
      with their email as id: sharing with them is an invitation.
    - ``GET <prefix>/groups/<id>/members/``: a group's members, as users. An
      application without groups of its own shares with each member. Listing
      them reports the group as picked, so it ranks higher next time.

    Register it in the application's router and subclass it to set throttles,
    the number of results, or what to leave out (``filter_results``).
    """

    permission_classes = [permissions.IsAuthenticated]
    search_limit = 10

    def get_search_limit(self):
        """Return the most results a search answers."""
        return self.search_limit

    def filter_results(self, results):
        """Return the results to suggest (e.g. leave out the users who already have access)."""
        return results

    def serialize_user(self, result):
        """Return a user result as the API answers it."""
        return {
            "kind": result.kind,
            "id": str(result.user.pk) if result.user is not None else result.email,
            "email": result.email,
            "full_name": result.name,
        }

    def serialize_group(self, result):
        """Return a group result as the API answers it."""
        return {
            "kind": GROUP,
            "id": result.group_id,
            "name": result.name,
            "email": result.email,
            "members_count": result.members_count,
        }

    def serialize(self, result):
        """Return a result as the API answers it."""
        return self.serialize_group(result) if result.kind == GROUP else self.serialize_user(result)

    def list(self, request):
        """Search the contacts to share with, best first."""
        results = search_contacts(request, request.query_params.get("q", ""), limit=self.get_search_limit())
        return Response([self.serialize(result) for result in self.filter_results(results)])

    @action(
        detail=False,
        methods=["get"],
        url_path=r"groups/(?P<group_id>[^/.]+)/members",
        url_name="group-members",
    )
    def group_members(self, request, group_id=None):
        """List the members of a group, to share with each of them."""
        backend = contact_search
        if not backend.supports_groups:
            raise exceptions.NotFound("Group not found.")
        try:
            members = backend.group_members(request.user, group_id, access_token=get_access_token(request, backend))
        except ContactSearchGroupNotFoundError as exc:
            raise exceptions.NotFound("Group not found.") from exc
        except ContactSearchUnavailableError as exc:
            raise GroupMembersUnavailable() from exc

        report_share(request, group_ids=[group_id])
        return Response([self.serialize_user(member) for member in members])
