"""Authentication Views for the OIDC authentication backend."""

import copy
from urllib.parse import urlencode

from django.contrib import auth
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils import crypto
from mozilla_django_oidc.utils import (
    absolutify,
)
from mozilla_django_oidc.views import (
    OIDCAuthenticationCallbackView as MozillaOIDCAuthenticationCallbackView,
)
from mozilla_django_oidc.views import (
    OIDCAuthenticationRequestView as MozillaOIDCAuthenticationRequestView,
)
from mozilla_django_oidc.views import (
    OIDCLogoutView as MozillaOIDCOIDCLogoutView,
)


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

        if state not in request.session.get("oidc_states", {}):
            msg = "OIDC callback state not found in session `oidc_states`!"
            raise SuspiciousOperation(msg)

        del request.session["oidc_states"][state]
        request.session.save()

        auth.logout(request)

        return HttpResponseRedirect(self.redirect_url)


class OIDCAuthenticationCallbackView(MozillaOIDCAuthenticationCallbackView):
    """Custom callback view for handling the silent login flow."""

    @property
    def failure_url(self):
        """
        Override the failure URL property to handle silent login flow.

        A silent login failure (e.g., no active user session) should not be
        considered as an authentication failure.
        """
        if self.request.session.get("silent", None):
            del self.request.session["silent"]
            self.request.session.save()
            return self.success_url
        return super().failure_url


class OIDCAuthenticationRequestView(MozillaOIDCAuthenticationRequestView):
    """Custom authentication view for handling the silent login flow."""

    def get_extra_params(self, request):
        """
        Handle 'prompt' extra parameter for the silent login flow.

        This extra parameter is necessary to distinguish between a standard
        authentication flow and the silent login flow.
        """
        extra_params = self.get_settings("OIDC_AUTH_REQUEST_EXTRA_PARAMS", None)
        if extra_params is None:
            extra_params = {}
        if request.GET.get("silent", "").lower() == "true":
            extra_params = copy.deepcopy(extra_params)
            extra_params.update({"prompt": "none"})
            request.session["silent"] = True
            request.session.save()
        return extra_params
