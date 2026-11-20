"""Tell the contact search backend about shares, so it can rank contacts."""

from django.db import transaction

from . import contact_search


def report_share(request, emails=(), *, group_ids=()):
    """
    Report that *request*'s user shared with *emails* and groups, once committed.

    Call it where the application creates accesses or invitations. Best effort:
    it runs after the share is saved and never fails it. A backend that needs
    the access token is skipped when the session holds none (e.g. a request
    from another application with its own token).
    """
    emails = [email for email in emails if email]
    group_ids = [group_id for group_id in group_ids if group_id]
    if not emails and not group_ids:
        return
    backend = contact_search
    access_token = None
    if backend.requires_access_token:
        session = getattr(request, "session", None)
        access_token = session.get("oidc_access_token") if session is not None else None
        if not access_token:
            return
    user = request.user
    transaction.on_commit(lambda: backend.record_share(user, emails, group_ids=group_ids, access_token=access_token))
