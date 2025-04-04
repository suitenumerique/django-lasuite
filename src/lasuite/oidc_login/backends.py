"""Authentication Backends for OIDC."""

import logging
from functools import lru_cache

import requests
from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import SuspiciousOperation
from django.utils.translation import gettext_lazy as _
from mozilla_django_oidc.auth import (
    OIDCAuthenticationBackend as MozillaOIDCAuthenticationBackend,
)
from mozilla_django_oidc.utils import import_from_settings

logger = logging.getLogger(__name__)


OIDC_USER_SUB_FIELD = getattr(
    settings,
    "OIDC_USER_SUB_FIELD",
    "sub",
)  # Default to 'sub' if not set in settings


@lru_cache(maxsize=1)
def get_cipher_suite():
    """Return a Fernet cipher suite."""
    key = import_from_settings("OIDC_STORE_REFRESH_TOKEN_KEY", None)
    if not key:
        raise ValueError("OIDC_STORE_REFRESH_TOKEN_KEY setting is required.")
    return Fernet(key)


def store_oidc_refresh_token(session, refresh_token):
    """Store the encrypted OIDC refresh token in the session if enabled in settings."""
    if import_from_settings("OIDC_STORE_REFRESH_TOKEN", False):
        encrypted_token = get_cipher_suite().encrypt(refresh_token.encode())
        session["oidc_refresh_token"] = encrypted_token.decode()


def get_oidc_refresh_token(session):
    """Retrieve and decrypt the OIDC refresh token from the session."""
    encrypted_token = session.get("oidc_refresh_token")
    if encrypted_token:
        return get_cipher_suite().decrypt(encrypted_token.encode()).decode()
    return None


def store_tokens(session, access_token, id_token, refresh_token):
    """Store tokens in the session if enabled in settings."""
    if import_from_settings("OIDC_STORE_ACCESS_TOKEN", False):
        session["oidc_access_token"] = access_token

    if import_from_settings("OIDC_STORE_ID_TOKEN", False):
        session["oidc_id_token"] = id_token

    store_oidc_refresh_token(session, refresh_token)


class OIDCAuthenticationBackend(MozillaOIDCAuthenticationBackend):
    """
    Custom OpenID Connect (OIDC) Authentication Backend.

    This class overrides the default OIDC Authentication Backend to accommodate differences
    in the User model, and handles signed and/or encrypted UserInfo response.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize the OIDC Authentication Backend.
        Adds an internal attribute to store the token_info dictionary.
        The purpose of `self._token_info` is to not duplicate code from
        the original `authenticate` method.
        This won't be needed after https://github.com/mozilla/mozilla-django-oidc/pull/377
        is merged.
        """
        super().__init__(*args, **kwargs)
        self._token_info = None

    def get_token(self, payload):
        """
        Return token object as a dictionary.
        Store the value to extract the refresh token in the `authenticate` method.
        """
        self._token_info = super().get_token(payload)
        return self._token_info

    def authenticate(self, request, **kwargs):
        """Authenticate a user based on the OIDC code flow."""
        user = super().authenticate(request, **kwargs)

        if user is not None:
            # Then the user successfully authenticated
            store_oidc_refresh_token(request.session, self._token_info.get("refresh_token"))

        return user

    def get_extra_claims(self, user_info):
        """
        Return extra claims from user_info.

        Args:
          user_info (dict): The user information dictionary.

        Returns:
          dict: A dictionary of extra claims.

        """
        return {
            "name": self.compute_full_name(user_info),
        }

    def post_get_or_create_user(self, user, claims):
        """
        Post-processing after user creation or retrieval.

        Args:
          user (User): The user instance.
          claims (dict): The claims dictionary.

        Returns:
        - None

        """

    def get_userinfo(self, access_token, id_token, payload):
        """
        Return user details dictionary.

        Args:
          access_token (str): The access token.
          id_token (str): The id token (unused).
          payload (dict): The token payload (unused).

        Note: The id_token and payload parameters are unused in this implementation,
        but were kept to preserve base method signature.

        Note: It handles signed and/or encrypted UserInfo Response. It is required by
        Agent Connect, which follows the OIDC standard. It forces us to override the
        base method, which deal with 'application/json' response.

        Returns:
          dict: User details dictionary obtained from the OpenID Connect user endpoint.

        """
        user_response = requests.get(
            self.OIDC_OP_USER_ENDPOINT,
            headers={"Authorization": f"Bearer {access_token}"},
            verify=self.get_settings("OIDC_VERIFY_SSL", True),
            timeout=self.get_settings("OIDC_TIMEOUT", None),
            proxies=self.get_settings("OIDC_PROXY", None),
        )
        user_response.raise_for_status()
        return self.verify_token(user_response.text)

    def get_or_create_user(self, access_token, id_token, payload):
        """
        Return a User based on userinfo. Create a new user if no match is found.

        Args:
          access_token (str): The access token.
          id_token (str): The ID token.
          payload (dict): The user payload.

        Returns:
          User: An existing or newly created User instance.

        Raises:
          Exception: Raised when user creation is not allowed and no existing user is found.

        """
        user_info = self.get_userinfo(access_token, id_token, payload)

        sub = user_info.get("sub")
        if not sub:
            raise SuspiciousOperation(_("User info contained no recognizable user identification"))

        # Get user's full name from OIDC fields defined in settings
        email = user_info.get("email")

        claims = {
            OIDC_USER_SUB_FIELD: sub,
            "email": email,
        }
        claims.update(**self.get_extra_claims(user_info))

        # if sub is absent, try matching on email
        user = self.get_existing_user(sub, email)

        if user:
            if not user.is_active:
                raise SuspiciousOperation(_("User account is disabled"))
            self.update_user_if_needed(user, claims)

        elif self.get_settings("OIDC_CREATE_USER", True):
            user = self.create_user(claims)

        self.post_get_or_create_user(user, claims)
        return user

    def create_user(self, claims):
        """Return a newly created User instance."""
        sub = claims.get("sub")
        if sub is None:
            raise SuspiciousOperation(_("Claims contained no recognizable user identification"))

        logger.info("Creating user %s", sub)

        user = self.UserModel(**claims)
        user.set_unusable_password()
        user.save()

        return user

    def compute_full_name(self, user_info):
        """Compute user's full name based on OIDC fields in settings."""
        name_fields = settings.USER_OIDC_FIELDS_TO_FULLNAME
        full_name = " ".join(user_info[field] for field in name_fields if user_info.get(field))
        return full_name or None

    def get_existing_user(self, sub, email):
        """Fetch existing user by sub or email."""
        try:
            return self.UserModel.objects.get(sub=sub)
        except self.UserModel.DoesNotExist:
            if email and settings.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION:
                try:
                    return self.UserModel.objects.get(email=email)
                except self.UserModel.DoesNotExist:
                    pass
        return None

    def update_user_if_needed(self, user, claims):
        """Update user claims if they have changed."""
        updated_claims = {}
        for key in claims:
            if not hasattr(user, key):
                continue

            claim_value = claims.get(key)
            if claim_value and claim_value != getattr(user, key):
                updated_claims[key] = claim_value

        if updated_claims:
            self.UserModel.objects.filter(sub=user.sub).update(**updated_claims)
