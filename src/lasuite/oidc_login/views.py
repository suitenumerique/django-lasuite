"""Authentication Views for the OIDC authentication backend."""

import copy
import logging
from importlib import import_module
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import auth
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils import crypto, timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from joserfc import jws, jwt
from joserfc.errors import DecodeError, JoseError
from joserfc.jwk import KeySet
from joserfc.util import to_bytes
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import absolutify, import_from_settings
from mozilla_django_oidc.views import (
    OIDCAuthenticationCallbackView as MozillaOIDCAuthenticationCallbackView,
)
from mozilla_django_oidc.views import (
    OIDCAuthenticationRequestView as MozillaOIDCAuthenticationRequestView,
)
from mozilla_django_oidc.views import (
    OIDCLogoutView as MozillaOIDCOIDCLogoutView,
)

User = get_user_model()

logger = logging.getLogger(__name__)


class OIDCLogoutView(MozillaOIDCOIDCLogoutView):
    """
    Custom logout view for handling OpenID Connect (OIDC) logout flow.

    Adds support for handling logout callbacks from the identity provider (OP)
    by initiating the logout flow if the user has an active session.

    The Django session is retained during the logout process to persist the 'state' OIDC parameter.
    This parameter is crucial for maintaining the integrity of the logout flow between this call
    and the subsequent callback.
    """

    @staticmethod
    def persist_state(request, state):
        """
        Persist the given 'state' parameter in the session's 'oidc_states' dictionary.

        This method is used to store the OIDC state parameter in the session, according to the
        structure expected by Mozilla Django OIDC's 'add_state_and_verifier_and_nonce_to_session'
        utility function.
        """
        if "oidc_states" not in request.session or not isinstance(request.session["oidc_states"], dict):
            request.session["oidc_states"] = {}

        request.session["oidc_states"][state] = {}

        # Force immediate session save for cache-based backends
        request.session.modified = True
        request.session.save()

    def construct_oidc_logout_url(self, request):
        """
        Create the redirect URL for interfacing with the OIDC provider.

        Retrieves the necessary parameters from the session and constructs the URL
        required to initiate logout with the OpenID Connect provider.

        If no ID token is found in the session, the logout flow will not be initiated,
        and the method will return the default redirect URL.

        The 'state' parameter is generated randomly and persisted in the session to ensure
        its integrity during the subsequent callback.
        """
        oidc_logout_endpoint = self.get_settings("OIDC_OP_LOGOUT_ENDPOINT")

        if not oidc_logout_endpoint:
            return self.redirect_url

        reverse_url = reverse("oidc_logout_callback")
        id_token = request.session.get("oidc_id_token", None)

        if not id_token:
            return self.redirect_url

        query = {
            "id_token_hint": id_token,
            "state": crypto.get_random_string(self.get_settings("OIDC_STATE_SIZE", 32)),
            "post_logout_redirect_uri": absolutify(request, reverse_url),
        }

        self.persist_state(request, query["state"])

        return f"{oidc_logout_endpoint}?{urlencode(query)}"

    def post(self, request):
        """
        Handle user logout.

        If the user is not authenticated, redirects to the default logout URL.
        Otherwise, constructs the OIDC logout URL and redirects the user to start
        the logout process.

        If the user is redirected to the default logout URL, ensure her Django session
        is terminated.
        """
        logout_url = self.redirect_url

        if request.user.is_authenticated:
            logout_url = self.construct_oidc_logout_url(request)

        # If the user is not redirected to the OIDC provider, ensure logout
        if logout_url == self.redirect_url:
            auth.logout(request)
        else:
            # Force final session save before redirect to SSO
            # This ensures the logout state generated in construct_oidc_logout_url()
            # is persisted in Redis before the browser redirects
            request.session.modified = True
            request.session.save()

        return HttpResponseRedirect(logout_url)


class OIDCLogoutCallbackView(MozillaOIDCOIDCLogoutView):
    """
    Custom view for handling the logout callback from the OpenID Connect (OIDC) provider.

    Handles the callback after logout from the identity provider (OP).
    Verifies the state parameter and performs necessary logout actions.

    The Django session is maintained during the logout process to ensure the integrity
    of the logout flow initiated in the previous step.
    """

    http_method_names = ["get"]

    def get(self, request):
        """
        Handle the logout callback.

        If the user is not authenticated, redirects to the default logout URL.
        Otherwise, verifies the state parameter and performs necessary logout actions.
        """
        if not request.user.is_authenticated:
            return HttpResponseRedirect(self.redirect_url)

        state = request.GET.get("state")

        # Handle requests without state parameter
        # Some SSO providers send a preflight request without state before the actual callback
        # We should not raise an error in this case, just redirect gracefully
        if not state:
            return HttpResponseRedirect(self.redirect_url)

        if state not in request.session.get("oidc_states", {}):
            msg = "OIDC callback state not found in session `oidc_states`!"
            raise SuspiciousOperation(msg)

        # Clean up the state from session
        del request.session["oidc_states"][state]
        request.session.save()

        # Perform Django logout
        auth.logout(request)

        return HttpResponseRedirect(self.redirect_url)


@method_decorator(csrf_exempt, name="dispatch")
class OIDCBackChannelLogoutView(View):
    """
    View to handle OIDC back-channel logout requests.

    This view implements the OpenID Connect Back-Channel Logout 1.0 specification
    (https://openid.net/specs/openid-connect-backchannel-1_0.html).

    The identity provider (IdP) sends a JWT Logout Token to this URL via
    a server-to-server POST request when a user logs out from
    another application or directly on the IdP.
    """

    http_method_names = ["post"]

    # OIDC Back-Channel Logout specification constants
    LOGOUT_EVENT_URI = "http://schemas.openid.net/event/backchannel-logout"
    LOGOUT_TOKEN_TYPE = "logout+jwt"  # noqa: S105

    # Recommended maximum duration for Logout Token expiration (2 minutes)
    MAX_TOKEN_AGE_SECONDS = 120

    # Cache key prefix for JTI storage
    JTI_CACHE_PREFIX = "oidc_backchannel_jti:"

    # Cache timeout (5 minutes - should be longer than MAX_TOKEN_AGE_SECONDS)
    JTI_CACHE_TIMEOUT = 300

    @staticmethod
    def get_settings(attr, *args):
        """Retrieve a parameter from Django settings."""
        return import_from_settings(attr, *args)

    def post(self, request, *args, **kwargs):  # noqa: PLR0911
        """
        Process the back-channel logout request.

        According to section 2.8 of the spec, returns:
        - 200 OK if logout succeeded
        - 204 No Content is also accepted (some Web frameworks)
        - 400 Bad Request if the request is invalid or logout fails

        Returns:
            HttpResponse: 200/204 on success, 400 on error

        """
        try:
            logout_token = self.get_logout_token(request)
            if not logout_token:
                logger.error("No logout_token provided in the request")
                return self.error_response("invalid_request", "Missing logout_token parameter")

            payload = self.validate_logout_token(logout_token)
            if not payload:
                return self.error_response("invalid_request", "Invalid logout token")

            # Check for presence of sub or sid (spec 2.4)
            sub = payload.get("sub")
            sid = payload.get("sid")

            if not sub and not sid:
                logger.error("Neither sub nor sid present in the logout token")
                return self.error_response("invalid_request", "Token must contain either sub or sid claim")

            # Check for token replay with jti
            jti = payload.get("jti")
            if jti and not self.check_and_store_jti(jti):
                logger.error("Logout token with jti=%s already processed (replay attack)", jti)
                return self.error_response("invalid_request", "Token already processed")

            # Log out user sessions
            success = self.logout_user_sessions(sub, sid)

            if success:
                logger.info("Back-channel logout successful for sub=%s, sid=%s", sub, sid)
                # According to the spec, return 204 No Content (or 200 OK w/ content)
                response = HttpResponse(status=204)
            else:
                logger.warning("Logout failed for sub=%s, sid=%s", sub, sid)
                return self.error_response("invalid_request", "Logout failed")

            # Spec 2.8: add Cache-Control: no-store
            response["Cache-Control"] = "no-store"
            return response

        except Exception as e:
            logger.exception("Error processing logout: %s", e)
            return self.error_response("invalid_request", "Internal server error during logout")

    def error_response(self, error, error_description=None):
        """
        Create an error response compliant with the spec (section 2.8).

        Args:
            error: OAuth 2.0 error code
            error_description: Optional error description

        Returns:
            JsonResponse: 400 Bad Request with JSON body

        """
        response_data = {"error": error}
        if error_description:
            response_data["error_description"] = error_description

        response = JsonResponse(response_data, status=400)
        response["Cache-Control"] = "no-store"
        return response

    def get_logout_token(self, request):
        """
        Extract the logout_token from the POST request.

        According to section 2.5 of the spec, the token must be in
        the request body as application/x-www-form-urlencoded.

        Args:
            request: The Django HTTP request

        Returns:
            str: The logout_token or None

        """
        return request.POST.get("logout_token")

    def validate_logout_token(self, logout_token):  # noqa: PLR0911
        """
        Validate and decode the logout_token JWT according to section 2.6 of the spec.

        Complete validation including:
        1. Type verification (typ header = "logout+jwt" recommended)
        2. Signature validation with OP's JWKS keys
        3. Issuer verification (iss)
        4. Audience verification (aud) - must contain client_id
        5. Expiration verification (exp) - recommended <= 2 minutes
        6. iat (issued at) verification
        7. Presence of jti claim (unique identifier)
        8. Presence of events claim with logout URI
        9. Absence of nonce claim (FORBIDDEN by spec to avoid confusion with ID Token)
        10. Presence of sub or sid

        Args:
            logout_token: The JWT to validate

        Returns:
            dict: Token payload if valid, None otherwise

        """
        try:
            # Check token type (recommended but not mandatory for compatibility)
            logout_token = to_bytes(logout_token)

            try:
                obj = jws.extract_compact(logout_token)
                header = obj.protected
                token_type = header.get("typ")
                if token_type and token_type.lower() != self.LOGOUT_TOKEN_TYPE:
                    logger.warning("Unexpected token type: %s (expected: %s)", token_type, self.LOGOUT_TOKEN_TYPE)
                    # Don't reject for compatibility with existing implementations
            except DecodeError:
                logger.error("Unable to decode JWT header")
                return None

            backend = OIDCAuthenticationBackend()

            # Retrieve OIDC provider's public key for signature validation
            jwks_client = backend.retrieve_matching_jwk(logout_token)

            # Decode token with complete validation
            keyset = KeySet.import_key_set({"keys": [jwks_client]})
            decoded_jwt = jwt.decode(logout_token, keyset, algorithms=["RS256", "ES256"])
            claims_requests = jwt.JWTClaimsRegistry(
                now=int(timezone.now().timestamp()),
                iss={"value": settings.OIDC_OP_URL, "essential": True},
                aud={"value": backend.OIDC_RP_CLIENT_ID, "essential": True},
                exp={"essential": True},
                iat={"essential": True},
            )
            claims_requests.validate(decoded_jwt.claims)
            payload = decoded_jwt.claims

            # Validation according to the spec (section 2.6)

            # 1. Verify that the 'events' claim exists and contains the correct URI
            if not self.is_valid_logout_event(payload):
                return None

            # 2. IMPORTANT: Verify ABSENCE of nonce (spec 2.4)
            if "nonce" in payload:
                logger.error("Logout token contains a 'nonce' claim (FORBIDDEN by the spec)")
                return None

            # 3. Verify presence of jti (unique identifier, REQUIRED)
            if "jti" not in payload:
                logger.error("Logout token does not contain 'jti' claim (REQUIRED)")
                return None

            # 4. Verify token is not too old (security recommendation)
            iat = payload.get("iat")
            exp = payload.get("exp")
            if iat and exp:
                token_lifetime = exp - iat
                if token_lifetime > self.MAX_TOKEN_AGE_SECONDS:
                    logger.warning(
                        "Logout token has a lifetime of %ss (recommended: <= %ss)",
                        token_lifetime,
                        self.MAX_TOKEN_AGE_SECONDS,
                    )

            return payload

        except JoseError as e:
            logger.exception("Invalid JWT token: %s", e)
            return None
        except Exception as e:
            logger.exception("Error validating token: %s", e)
            return None

    def is_valid_logout_event(self, payload):
        """
        Verify that the payload contains a valid logout event.

        According to section 2.4 of the spec, the 'events' claim must:
        - Be a JSON object
        - Contain the key "http://schemas.openid.net/event/backchannel-logout"
        - The value must be a JSON object (recommended: empty object {})

        Args:
            payload: The decoded JWT payload

        Returns:
            bool: True if the event is valid

        """
        events = payload.get("events")

        if not events or not isinstance(events, dict):
            logger.error("Invalid token: 'events' claim absent or not an object")
            return False

        if self.LOGOUT_EVENT_URI not in events:
            logger.error("Incorrect event type: %s not found in events", self.LOGOUT_EVENT_URI)
            return False

        # The value must be a JSON object
        event_value = events[self.LOGOUT_EVENT_URI]
        if not isinstance(event_value, dict):
            logger.error("Logout event value must be a JSON object")
            return False

        return True

    def check_and_store_jti(self, jti):
        """
        Check if the jti has already been processed and store it to prevent replay.

        Uses Django's cache framework (configured in settings.py) to store JTIs.
        This allows the implementation to work correctly across multiple server instances
        and persist data appropriately based on the configured cache backend.

        Recommended cache backends for production:
        - Redis: Shared state across instances, fast, with TTL support
        - Memcached: Similar benefits to Redis
        - Database: Persistent but slower

        The cache timeout is set to 5 minutes (longer than MAX_TOKEN_AGE_SECONDS)
        to ensure tokens can't be replayed even if received near expiration.

        Args:
            jti: The unique token identifier

        Returns:
            bool: True if the jti is new, False if it has already been processed

        """
        cache_key = f"{self.JTI_CACHE_PREFIX}{jti}"

        # Try to add the jti to cache (atomic operation)
        # add() returns False if key already exists, True if successfully added
        was_added = cache.add(cache_key, True, timeout=self.JTI_CACHE_TIMEOUT)

        if not was_added:
            logger.warning("JTI %s already exists in cache (replay attack detected)", jti)
            return False

        logger.debug("JTI %s stored in cache with %ss timeout", jti, self.JTI_CACHE_TIMEOUT)
        return True

    def logout_user_sessions(self, sub, sid=None):  # noqa: PLR0912,PLR0915
        """
        Log out sessions associated with a user (section 2.7 of the spec).

        According to the spec:
        - If sid is present: log out only that specific session
        - If only sub is present: log out ALL user sessions
        - If both are present: implementation can choose

        This method should also:
        - Revoke refresh tokens (except those with offline_access)
        - If the RP is also an OP, propagate logout to downstream RPs

        Args:
            sub: User's subject identifier (unique OIDC identifier)
            sid: Session ID (optional, to target a specific session)

        Returns:
            bool: True if at least one session was logged out, False otherwise

        """
        session_store = import_module(settings.SESSION_ENGINE).SessionStore()

        user = None
        sessions_deleted = 0

        if settings.SESSION_ENGINE not in [
            "django.contrib.sessions.backends.db",
            "django.contrib.sessions.backends.cached_db",
        ]:
            logger.error(
                "OIDC back-channel logout requires database-backed sessions. Current SESSION_ENGINE: %s",
                settings.SESSION_ENGINE,
            )
            return False

        # Case 1: sub is provided - resolve user first (original behavior)
        if sub is not None:
            try:
                user = User.objects.get(sub=sub)
            except User.DoesNotExist:
                logger.warning("User with sub=%s not found", sub)
                # According to the spec, if the user is already logged out, consider it a success
                return True
            except User.MultipleObjectsReturned:
                logger.error("Multiple users with the same sub=%s", sub)
                return False

            # Iterate through all active sessions
            sessions = Session.objects.filter(expire_date__gte=timezone.now())

            for session in sessions:
                try:
                    session_data = session.get_decoded()
                    session_user_id = session_data.get("_auth_user_id")

                    if session_user_id and str(session_user_id) == str(user.pk):
                        # If a specific sid is provided, check for match
                        session_sid = session_data.get("oidc_sid")
                        if session_sid and sid and session_sid == sid:
                            session_store.delete(session.session_key)
                            sessions_deleted += 1
                            break  # Only one session matches the sid
                        if not session_sid or not sid:
                            # Delete all user sessions or sessions without sid
                            session_store.delete(session.session_key)
                            sessions_deleted += 1
                except Exception as e:
                    logger.error("Error processing session: %s", e)
                    continue

        # Case 2: only sid is provided - find session first, then resolve user lazily
        elif sid is not None:
            # Iterate through all active sessions looking for the specific sid
            sessions = Session.objects.filter(expire_date__gte=timezone.now())

            for session in sessions:
                try:
                    session_data = session.get_decoded()
                    session_sid = session_data.get("oidc_sid")
                    if session_sid != sid:
                        continue

                    # Found matching session, now lazily resolve the user
                    session_user_id = session_data.get("_auth_user_id")
                    if session_user_id:
                        try:
                            user = User.objects.get(pk=session_user_id)
                            session_store.delete(session.session_key)
                            sessions_deleted += 1
                            logger.info("Session %s deleted for user %s", sid, user.pk)
                            break  # Only one session matches the sid
                        except User.DoesNotExist:
                            logger.warning("User with pk=%s not found for session %s", session_user_id, sid)
                            # Still delete the orphaned session
                            session_store.delete(session.session_key)
                            sessions_deleted += 1
                            logger.info("Orphaned session %s deleted", sid)
                            break
                        except (ValueError, TypeError) as e:
                            logger.error("Invalid user_id %s in session %s: %s", session_user_id, sid, e)
                            continue
                    else:
                        logger.warning("No user_id found in session %s", sid)
                        # Still delete the session without user context
                        session_store.delete(session.session_key)
                        sessions_deleted += 1
                        logger.info("Anonymous session %s deleted", sid)
                        break
                except Exception as e:
                    logger.error("Error processing session: %s", e)
                    continue

        else:
            # Neither sub nor sid provided - this shouldn't happen due to validation in post()
            logger.error("Neither sub nor sid provided for logout")
            return False

        if sessions_deleted > 0:
            if user:
                logger.info("%s session(s) deleted for user %s", sessions_deleted, user.pk)
            else:
                logger.info("%s session(s) deleted", sessions_deleted)
        # According to spec 2.7, if the user is already logged out, it's a success
        elif user:
            logger.info("No active session found for user %s (already logged out)", user.pk)
        else:
            logger.info("No active session found for sid %s (already logged out)", sid)

        # Only call user-related methods if we successfully resolved a user
        if user:
            self.revoke_refresh_tokens(user)
            self.propagate_logout_to_downstream_rps(user, sub, sid)

        return True

    def revoke_refresh_tokens(self, user):
        """
        Revoke user's refresh tokens (section 2.7 of the spec).

        According to the spec:
        - Refresh tokens WITHOUT offline_access MUST be revoked
        - Refresh tokens WITH offline_access MUST NOT be revoked normally

        NOTE: This implementation depends on the token management system.
        To be implemented if needed by the project

        Args:
            user: The user whose tokens should be revoked

        """

    def propagate_logout_to_downstream_rps(self, user, sub, sid):
        """
        Propagate logout to downstream RPs if this RP is also an OP.

        According to section 2.7 of the spec, if the RP receiving the logout
        is itself an OP serving other RPs, it should propagate
        the logout by sending logout requests to its own RPs.

        NOTE: To be implemented if needed by the project.

        Args:
            user: The user to log out
            sub: Subject identifier
            sid: Session ID (optional)

        """


class OIDCAuthenticationCallbackView(MozillaOIDCAuthenticationCallbackView):
    """Custom callback view for handling silent login failure with state validation."""

    def get(self, request):
        """Handle silent login failure with CSRF protection via state validation."""
        error = request.GET.get("error")
        state = request.GET.get("state")

        # Validate state parameter even during silent login failures to prevent CSRF
        if error == "login_required" and request.session.get("silent"):
            if state and state in request.session.get("oidc_states", {}):
                # Keep state for potential subsequent SSO callback with authorization code
                del request.session["silent"]
                request.session.save()
                return HttpResponseRedirect(self.success_url)
            msg = "OIDC callback state validation failed during silent login"
            raise SuspiciousOperation(msg)

        return super().get(request)

    @property
    def failure_url(self):
        """
        Override the failure URL property to handle silent login flow.

        A silent login failure (e.g., no active user session) should redirect
        to success_url (homepage) instead of failure_url, because it's not
        really a failure - it just means the user needs to log in manually.
        """
        if self.request.session.get("silent", None):
            # Clean up silent flag
            del self.request.session["silent"]
            self.request.session.save()
            # Redirect to success URL (homepage) instead of failure page
            return self.success_url
        return super().failure_url


class OIDCAuthenticationRequestView(MozillaOIDCAuthenticationRequestView):
    """Custom authentication view for handling the silent login flow."""

    def get(self, request):
        """Force session persistence before redirect to SSO provider."""
        if not request.session.session_key:
            request.session.create()

        response = super().get(request)

        if hasattr(request, "session"):
            request.session.modified = True
            request.session.save()

        return response

    def get_extra_params(self, request):
        """
        Handle 'prompt' extra parameter for the silent login flow.

        Silent login (?silent=true) adds prompt=none to check for active
        SSO session without displaying UI.
        """
        extra_params = self.get_settings("OIDC_AUTH_REQUEST_EXTRA_PARAMS", None)
        if extra_params is None:
            extra_params = {}

        if request.GET.get("silent", "").lower() == "true":
            extra_params = copy.deepcopy(extra_params)
            extra_params.update({"prompt": "none"})
            request.session["silent"] = True

        return extra_params
