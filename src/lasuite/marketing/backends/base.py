"""Marketing backend base module."""

from abc import ABC, abstractmethod

from lasuite.marketing.backends import ContactData


class BaseBackend(ABC):
    """Base class for all marketing backends."""

    @abstractmethod
    def create_or_update_contact(self, contact_data: ContactData, timeout: int = None) -> dict:
        """
        Create or update a contact.

        Args:
            contact_data: Contact information and attributes
            timeout: API request timeout in seconds

        Returns:
            dict: Service response

        Raises:
            ContactCreationError: If contact creation fails

        """
