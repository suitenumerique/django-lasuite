"""Test the marketing tasks."""

from unittest import mock

from lasuite.marketing import tasks
from lasuite.marketing.backends import ContactData


def test_create_or_update_contact_success():
    """Test the create_or_update_contact task."""
    with mock.patch.object(tasks, "marketing") as mock_marketing:
        mock_marketing.create_or_update_contact = mock.MagicMock()

        contact_data = ContactData(
            email="test@example.com",
            attributes={"first_name": "Test"},
            list_ids=[1, 2],
            update_enabled=True,
        )

        tasks.create_or_update_contact(
            email="test@example.com", attributes={"first_name": "Test"}, list_ids=[1, 2], update_enabled=True
        )

        mock_marketing.create_or_update_contact.assert_called_once_with(contact_data, None)


def test_create_or_update_contact_with_timeout():
    """Test the create_or_update_contact task."""
    with mock.patch.object(tasks, "marketing") as mock_marketing:
        mock_marketing.create_or_update_contact = mock.MagicMock()

        contact_data = ContactData(
            email="test@example.com",
            attributes={"first_name": "Test"},
            list_ids=[1, 2],
            update_enabled=True,
        )

        tasks.create_or_update_contact(
            email="test@example.com",
            attributes={"first_name": "Test"},
            list_ids=[1, 2],
            update_enabled=True,
            timeout=30,
        )

        mock_marketing.create_or_update_contact.assert_called_once_with(contact_data, 30)
