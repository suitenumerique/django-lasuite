"""Contact search exceptions."""


class ContactSearchError(Exception):
    """Base exception for all contact search exceptions."""


class ContactSearchInvalidBackendError(ContactSearchError):
    """The configured backend can't be imported."""


class ContactSearchUnavailableError(ContactSearchError):
    """The backend can't answer now (service down, slow, token refused)."""


class ContactSearchGroupNotFoundError(ContactSearchError):
    """The backend has no such group, or the user can't see it."""
