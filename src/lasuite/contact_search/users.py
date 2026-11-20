"""Match the addresses a backend found to the application's users."""

import string

from django.contrib.auth import get_user_model

from .backends import USER, ContactResult

_ASCII_LOWERCASE = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def normalize_email(email):
    """Strip an email and lowercase its ASCII letters only."""
    return (email or "").strip().translate(_ASCII_LOWERCASE)


class UserMatchingMixin:
    """
    Turn the addresses a backend found into users to share with.

    An address of exactly one active user becomes that user: sharing gives
    them access. An address no account uses becomes an invitation. Any other
    address is left out: an invitation to it would be refused, and an access
    for an inactive or ambiguous account is meaningless. So are an empty
    address and the user's own.

    Every step is a method, to override when the user model differs from what
    the defaults expect.
    """

    def normalize_email(self, email):
        """Return *email* as the application stores and compares addresses."""
        return normalize_email(email)

    def get_users_by_email(self, emails):
        """
        Return the accounts using each of *emails*, as ``{email: [user, ...]}``.

        Compares the normalized addresses with the user model's email field
        (``EMAIL_FIELD``) exactly, so the database index serves it.
        """
        user_model = get_user_model()
        field = user_model.get_email_field_name()
        accounts = {}
        for account in user_model._default_manager.filter(**{f"{field}__in": list(emails)}):  # noqa: SLF001
            accounts.setdefault(self.normalize_email(getattr(account, field)), []).append(account)
        return accounts

    def can_share_with(self, account):
        """Tell whether *account* may be given access."""
        return getattr(account, "is_active", True)

    def get_user_name(self, account, default=""):
        """Return the name to show for *account*, else *default* (the name the backend found)."""
        get_full_name = getattr(account, "get_full_name", None)
        return (get_full_name() if callable(get_full_name) else "") or default

    def match_users(self, user, people):
        """
        Turn ``{email: name}`` into ``{email: ContactResult}``, in the same order.

        Args:
            user: The user sharing (their own address is left out)
            people: The names the backend found, by normalized address

        """
        own = self.normalize_email(getattr(user, user.get_email_field_name(), ""))
        people = {email: name for email, name in people.items() if email and email != own}
        accounts = self.get_users_by_email(people)

        results = {}
        for email, name in people.items():
            matches = accounts.get(email, [])
            if not matches:
                results[email] = ContactResult(kind=USER, email=email, name=name)
            elif len(matches) == 1 and self.can_share_with(matches[0]):
                found = matches[0]
                results[email] = ContactResult(kind=USER, email=email, name=self.get_user_name(found, name), user=found)
        return results
