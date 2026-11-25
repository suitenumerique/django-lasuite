"""Test the Brevo marketing backend."""

import pytest

from lasuite.marketing.backends import ContactData
from lasuite.marketing.backends.brevo import BrevoBackend
from lasuite.marketing.exceptions import ContactCreationError


def test_create_contact_success_without_existing_brevo_contact(httpx2_mock):
    """Test successful contact creation."""
    httpx2_mock.add_response(
        method="GET",
        url="https://api.brevo.com/v3/contacts/test%40example.com?identifierType=email_id",
        status_code=404,
    )

    httpx2_mock.add_response(
        method="POST",
        url="https://api.brevo.com/v3/contacts",
        json={
            "id": "test-id",
        },
        status_code=201,
        match_json={
            "email": "test@example.com",
            "updateEnabled": True,
            "listIds": [1, 2, 3],
            "attributes": {"source": "test", "first_name": "Test"},
        },
        headers={"api-key": "test-api-key"},
    )

    valid_contact_data = ContactData(
        email="test@example.com",
        attributes={"first_name": "Test"},
        list_ids=[1, 2],
        update_enabled=True,
    )

    brevo_service = BrevoBackend(
        api_key="test-api-key",
        api_contact_list_ids=[1, 2, 3],
        api_contact_attributes={"source": "test"},
    )

    response = brevo_service.create_or_update_contact(valid_contact_data)

    assert response == {"id": "test-id"}


def test_create_contact_success_with_existing_brevo_contact(httpx2_mock):
    """Test successful contact creation."""
    httpx2_mock.add_response(
        method="GET",
        url="https://api.brevo.com/v3/contacts/test%40example.com?identifierType=email_id",
        status_code=200,
        json={"id": "test-id", "listIds": [4, 5]},
    )

    httpx2_mock.add_response(
        method="POST",
        url="https://api.brevo.com/v3/contacts",
        json={"id": "test-id"},
        status_code=201,
        match_json={
            "email": "test@example.com",
            "updateEnabled": True,
            "listIds": [1, 2, 3, 4, 5],
            "attributes": {"source": "test", "first_name": "Test"},
        },
        headers={"api-key": "test-api-key"},
    )

    valid_contact_data = ContactData(
        email="test@example.com",
        attributes={"first_name": "Test"},
        list_ids=[1, 2],
        update_enabled=True,
    )

    brevo_service = BrevoBackend(
        api_key="test-api-key",
        api_contact_list_ids=[1, 2, 3],
        api_contact_attributes={"source": "test"},
    )

    response = brevo_service.create_or_update_contact(valid_contact_data)

    assert response == {"id": "test-id"}


def test_create_contact_api_error(httpx2_mock):
    """Test contact creation API error handling."""
    httpx2_mock.add_response(
        method="GET",
        url="https://api.brevo.com/v3/contacts/test%40example.com?identifierType=email_id",
        status_code=404,
    )

    httpx2_mock.add_response(
        method="POST",
        url="https://api.brevo.com/v3/contacts",
        json={"id": "test-id"},
        status_code=400,
        match_json={
            "email": "test@example.com",
            "updateEnabled": True,
            "listIds": [1, 2, 3],
            "attributes": {"source": "test", "first_name": "Test"},
        },
        headers={"api-key": "test-api-key"},
    )

    valid_contact_data = ContactData(
        email="test@example.com",
        attributes={"first_name": "Test"},
        list_ids=[1, 2],
        update_enabled=True,
    )

    brevo_service = BrevoBackend(
        api_key="test-api-key",
        api_contact_list_ids=[1, 2, 3],
        api_contact_attributes={"source": "test"},
    )

    with pytest.raises(ContactCreationError, match="Failed to create contact in Brevo"):
        brevo_service.create_or_update_contact(valid_contact_data)


def test_create_contact_ignores_malformed_existing_contact(httpx2_mock):
    """A non-JSON lookup response is treated as an unknown contact."""
    httpx2_mock.add_response(
        method="GET",
        url="https://api.brevo.com/v3/contacts/test%40example.com?identifierType=email_id",
        text="not json",
    )
    httpx2_mock.add_response(
        method="POST", url="https://api.brevo.com/v3/contacts", json={"id": "test-id"}, status_code=201
    )

    backend = BrevoBackend(api_key="test-api-key", api_contact_list_ids=[1])
    result = backend.create_or_update_contact(ContactData(email="test@example.com"))

    assert result == {"id": "test-id"}
