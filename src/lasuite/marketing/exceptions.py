"""Marketing exceptions module."""


class MarketingError(Exception):
    """Base exception for all marketing exceptions."""


class MarketingInvalidBackendError(MarketingError):
    """Exception raised when the backend is invalid."""


class ContactCreationError(MarketingError):
    """Exception raised when the contact creation fails."""
