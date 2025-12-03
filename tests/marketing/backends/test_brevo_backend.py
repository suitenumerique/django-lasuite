"""Test the Brevo marketing backend."""

import pytest
import responses
from responses import matchers

from lasuite.marketing.backends import ContactData
from lasuite.marketing.backends.brevo import BrevoBackend
from lasuite.marketing.exceptions import ContactCreationError


@responses.activate
def test_create_contact_success_without_existing_brevo_contact():
    """Test successful contact creation."""
    responses.add(
        responses.GET,
        "https://api.brevo.com/v3/contacts/test%40example.com?identifierType=email_id",
        status=404,
    )

    responses.add(
        responses.POST,
        "https://api.brevo.com/v3/contacts",
        headers={"api-key": "test-api-key"},
        json={
            "id": "test-id",
        },
        status=201,
        match=[
            matchers.json_params_matcher(
                {
                    "email": "test@example.com",
                    "updateEnabled": True,
                    "listIds": [1, 2, 3],
                    "attributes": {"source": "test", "first_name": "Test"},
                }
            )
        ],
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


@responses.activate
def test_create_contact_success_with_existing_brevo_contact():
    """Test successful contact creation."""
    responses.add(
        responses.GET,
        "https://api.brevo.com/v3/contacts/test%40example.com?identifierType=email_id",
        status=200,
        json={"id": "test-id", "listIds": [4, 5]},
    )

    responses.add(
        responses.POST,
        "https://api.brevo.com/v3/contacts",
        headers={"api-key": "test-api-key"},
        json={"id": "test-id"},
        status=201,
        match=[
            matchers.json_params_matcher(
                {
                    "email": "test@example.com",
                    "updateEnabled": True,
                    "listIds": [1, 2, 3, 4, 5],
                    "attributes": {"source": "test", "first_name": "Test"},
                }
            )
        ],
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


@responses.activate
def test_create_contact_api_error():
    """Test contact creation API error handling."""
    responses.add(
        responses.GET,
        "https://api.brevo.com/v3/contacts/test%40example.com?identifierType=email_id",
        status=404,
    )

    responses.add(
        responses.POST,
        "https://api.brevo.com/v3/contacts",
        headers={"api-key": "test-api-key"},
        json={"id": "test-id"},
        status=400,
        match=[
            matchers.json_params_matcher(
                {
                    "email": "test@example.com",
                    "updateEnabled": True,
                    "listIds": [1, 2, 3],
                    "attributes": {"source": "test", "first_name": "Test"},
                }
            )
        ],
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
