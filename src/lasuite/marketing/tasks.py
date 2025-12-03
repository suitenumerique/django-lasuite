"""Marketing tasks module."""

from celery import shared_task

from lasuite.marketing import marketing
from lasuite.marketing.backends import ContactData


@shared_task
def create_or_update_contact(
    email: str,
    attributes: dict[str, str] | None = None,
    list_ids: list[int] | None = None,
    update_enabled: bool = True,
    timeout: int = None,
):
    """Create or update a contact."""
    contact_data = ContactData(email=email, attributes=attributes, list_ids=list_ids, update_enabled=update_enabled)
    return marketing.create_or_update_contact(contact_data, timeout)
