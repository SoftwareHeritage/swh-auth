# Copyright (C) 2020-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from typing import Any, Dict, cast
import uuid

from django.conf.urls import url
from django.contrib.auth import authenticate, login, logout
from django.core.cache import cache
from django.http import HttpRequest
from django.http.response import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
    HttpResponseServerError,
)

from swh.auth.django.models import OIDCUser
from swh.auth.django.utils import keycloak_oidc_client, oidc_profile_cache_key, reverse
from swh.auth.keycloak import KeycloakError, keycloak_error_message
from swh.auth.utils import gen_oidc_pkce_codes


def oidc_login_view(request: HttpRequest, redirect_uri: str, scope: str = "openid"):
    """
    Helper view function that initiates a login process using OIDC authorization
    code flow with PKCE.

    OIDC session scope can be modified using the dedicated parameter.
    """
    # generate a CSRF token
    state = str(uuid.uuid4())

    code_verifier, code_challenge = gen_oidc_pkce_codes()

    request.session["login_data"] = {
        "code_verifier": code_verifier,
        "state": state,
        "redirect_uri": redirect_uri,
        "next_path": request.GET.get("next_path", ""),
    }

    authorization_url_params = {
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "scope": scope,
    }

    try:
        oidc_client = keycloak_oidc_client()
        authorization_url = oidc_client.authorization_url(
            redirect_uri, **authorization_url_params
        )
    except KeycloakError as ke:
        return HttpResponseServerError(keycloak_error_message(ke))

    return HttpResponseRedirect(authorization_url)


def get_oidc_login_data(request: HttpRequest) -> Dict[str, Any]:
    """
    Check and get login data stored in django session.
    """
    if "login_data" not in request.session:
        raise Exception("Login process has not been initialized.")

    login_data = request.session["login_data"]

    if "code" not in request.GET or "state" not in request.GET:
        raise ValueError("Missing query parameters for authentication.")

    # get CSRF token returned by OIDC server
    state = request.GET["state"]

    if state != login_data["state"]:
        raise ValueError("Wrong CSRF token, aborting login process.")

    return login_data


def oidc_login(request: HttpRequest) -> HttpResponse:
    """
    Django view to initiate login process using OpenID Connect authorization
    code flow with PKCE.
    """

    redirect_uri = reverse("oidc-login-complete", request=request)

    return oidc_login_view(request, redirect_uri=redirect_uri)


def oidc_login_complete(request: HttpRequest) -> HttpResponse:
    """
    Django view to finalize login process using OpenID Connect authorization
    code flow with PKCE.
    """
    if "error" in request.GET:
        return HttpResponseServerError(request.GET["error"])

    try:
        login_data = get_oidc_login_data(request)
    except ValueError as ve:
        return HttpResponseBadRequest(str(ve))
    except Exception as e:
        return HttpResponseServerError(str(e))

    next_path = login_data["next_path"] or request.build_absolute_uri("/")

    user = authenticate(
        request=request,
        code=request.GET["code"],
        code_verifier=login_data["code_verifier"],
        redirect_uri=login_data["redirect_uri"],
    )

    if user is None:
        return HttpResponseServerError("User authentication failed.")

    login(request, user)

    return HttpResponseRedirect(next_path)


def oidc_logout(request: HttpRequest) -> HttpResponse:
    """
    Django view to logout using OpenID Connect.
    """
    user = request.user
    logout(request)
    if hasattr(user, "refresh_token"):
        user = cast(OIDCUser, user)
        refresh_token = cast(str, user.refresh_token)
        try:
            # end OpenID Connect session
            oidc_client = keycloak_oidc_client()
            oidc_client.logout(refresh_token)
        except KeycloakError as ke:
            return HttpResponseServerError(keycloak_error_message(ke))
        # remove user data from cache
        cache.delete(oidc_profile_cache_key(oidc_client, user.id))

    return HttpResponseRedirect(request.GET.get("next_path", "/"))


urlpatterns = [
    url(r"^oidc/login/$", oidc_login, name="oidc-login"),
    url(r"^oidc/login-complete/$", oidc_login_complete, name="oidc-login-complete"),
    url(r"^oidc/logout/$", oidc_logout, name="oidc-logout"),
]
