"""Brevo marketing automation integration."""

import logging
from urllib.parse import quote_plus

import requests

from lasuite.marketing.backends import ContactData
from lasuite.marketing.exceptions import ContactCreationError

from .base import BaseBackend

logger = logging.getLogger(__name__)


class BrevoBackend(BaseBackend):
    """
    Brevo marketing automation integration.

    Handles:
    - Contact management and segmentation
    - Marketing campaigns and automation
    - Email communications
    """

    def __init__(self, api_key: str, api_contact_list_ids: list[int], api_contact_attributes: dict | None = None):
        """Configure the Brevo backend."""
        self._api_key = api_key
        self.api_contact_attributes = api_contact_attributes or {}
        self.api_contact_list_ids = api_contact_list_ids

    def create_or_update_contact(self, contact_data: ContactData, timeout: int = None) -> dict:
        """
        Create or update a Brevo contact.

        Args:
            contact_data: Contact information and attributes
            timeout: API request timeout in seconds

        Returns:
            dict: Brevo API response

        Raises:
            ContactCreationError: If contact creation fails
            ImproperlyConfigured: If required settings are missing

        Note:
            Contact attributes must be pre-configured in Brevo.
            Changes to attributes can impact existing workflows.

        """
        # First try to retrieve the contact by email
        try:
            email = quote_plus(contact_data.email)
            url = f"https://api.brevo.com/v3/contacts/{email}"
            response = requests.get(
                url, params={"identifierType": "email_id"}, headers={"api-key": self._api_key}, timeout=timeout or 10
            )
            response.raise_for_status()
            contact = response.json()
        except requests.RequestException:
            pass
        else:
            # Add the list_ids from the contact in the contact_data
            list_ids = contact.get("listIds", [])
            contact_data.list_ids = (contact_data.list_ids or []) + list_ids

        attributes = {
            **self.api_contact_attributes,
            **(contact_data.attributes or {}),
        }

        # Use a set to avoid duplicates
        list_ids = set((contact_data.list_ids or []) + self.api_contact_list_ids)

        payload = {
            "email": contact_data.email,
            "updateEnabled": contact_data.update_enabled,
            "listIds": list(list_ids),
            "attributes": attributes,
        }

        print(payload)

        try:
            response = requests.post(
                "https://api.brevo.com/v3/contacts",
                json=payload,
                headers={"api-key": self._api_key},
                timeout=timeout or 10,
            )
            response.raise_for_status()
        except requests.RequestException as err:
            raise ContactCreationError("Failed to create contact in Brevo") from err

        if response.status_code == requests.codes.created:
            return response.json()

        return {}
