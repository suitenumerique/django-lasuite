"""Authentication Backends for OIDC."""

import logging
from functools import lru_cache
from json import JSONDecodeError

import requests
from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import SuspiciousOperation
from django.utils.translation import gettext_lazy as _
from mozilla_django_oidc.auth import (
    OIDCAuthenticationBackend as MozillaOIDCAuthenticationBackend,
)
from mozilla_django_oidc.utils import import_from_settings

from lasuite.oidc_login.enums import OIDCUserEndpointFormat
from lasuite.oidc_login.exceptions import DuplicateEmailError

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

        Sets the `OIDC_OP_USER_ENDPOINT_FORMAT` based on the settings, with fallback on "auto" mode.
        This allows to enforce specific behavior for the user endpoint format (if you want to enforce
        JWT use or JSON use).
        """
        super().__init__(*args, **kwargs)
        self._token_info = None

        self.OIDC_OP_USER_ENDPOINT_FORMAT = OIDCUserEndpointFormat[
            self.get_settings(
                "OIDC_OP_USER_ENDPOINT_FORMAT",
                OIDCUserEndpointFormat.AUTO.name,
            )
        ]
        self.USER_OIDC_ESSENTIAL_CLAIMS = self.get_settings("USER_OIDC_ESSENTIAL_CLAIMS", [])
        self.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = self.get_settings(
            "OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION",
            True,
        )
        self.OIDC_ALLOW_DUPLICATE_EMAILS = self.get_settings(
            "OIDC_ALLOW_DUPLICATE_EMAILS",
            False,
        )

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
            # Get user's full name from OIDC fields defined in settings
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

        _expected_format = self.OIDC_OP_USER_ENDPOINT_FORMAT
        if self.OIDC_OP_USER_ENDPOINT_FORMAT == OIDCUserEndpointFormat.AUTO:
            # In auto mode, we check the content type of the response to determine
            # the expected format.
            if user_response.headers.get("Content-Type") == "application/jwt":
                _expected_format = OIDCUserEndpointFormat.JWT
            else:
                _expected_format = OIDCUserEndpointFormat.JSON

        if _expected_format == OIDCUserEndpointFormat.JWT:
            try:
                userinfo = self.verify_token(user_response.text)
            except UnicodeDecodeError as exc:
                raise SuspiciousOperation("User info response was not valid JWT") from exc
        else:
            try:
                userinfo = user_response.json()
            except (JSONDecodeError, UnicodeDecodeError) as exc:
                raise SuspiciousOperation("User info response was not valid JSON") from exc

        return userinfo

    def verify_claims(self, claims):
        """
        Verify the presence of essential claims and the "sub" (which is mandatory as defined
        by the OIDC specification) to decide if authentication should be allowed.
        """
        essential_claims = set(self.USER_OIDC_ESSENTIAL_CLAIMS) | {"sub"}
        missing_claims = [claim for claim in essential_claims if claim not in claims]

        if missing_claims:
            logger.error("Missing essential claims: %s", ", ".join(missing_claims))
            return False

        return True

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

        if not self.verify_claims(user_info):
            msg = "Claims verification failed"
            raise SuspiciousOperation(msg)

        sub = user_info["sub"]
        email = user_info.get("email")

        claims = {
            OIDC_USER_SUB_FIELD: sub,
            "email": email,
        }
        claims.update(**self.get_extra_claims(user_info))

        # if sub is absent, try matching on email
        try:
            user = self.get_existing_user(sub, email)
        except DuplicateEmailError as exc:
            raise SuspiciousOperation(exc.message) from exc

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
        except self.UserModel.DoesNotExist as err:
            if not email:
                return None

            if self.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION:
                try:
                    return self.UserModel.objects.get(email=email)
                except self.UserModel.DoesNotExist:
                    pass

            elif self.UserModel.objects.filter(email=email).exists() and not self.OIDC_ALLOW_DUPLICATE_EMAILS:
                raise DuplicateEmailError(
                    "We couldn't find a user with this sub but the email is already associated with a registered user."
                ) from err
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
