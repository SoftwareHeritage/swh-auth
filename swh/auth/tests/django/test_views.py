# Copyright (C) 2020-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

import json
from urllib.parse import urljoin, urlparse
import uuid

from django.contrib.auth.models import AnonymousUser, User
from django.http import QueryDict
import pytest

from swh.auth.django.models import OIDCUser
from swh.auth.django.utils import reverse
from swh.auth.keycloak import KeycloakError
from swh.auth.tests.django.django_asserts import assert_contains
from swh.auth.tests.sample_data import CLIENT_ID


def _check_oidc_login_code_flow_data(
    request, response, keycloak_oidc, redirect_uri, scope="openid"
):
    parsed_url = urlparse(response["location"])

    authorization_url = keycloak_oidc.well_known()["authorization_endpoint"]
    query_dict = QueryDict(parsed_url.query)

    # check redirect url is valid
    assert urljoin(response["location"], parsed_url.path) == authorization_url
    assert "client_id" in query_dict
    assert query_dict["client_id"] == CLIENT_ID
    assert "response_type" in query_dict
    assert query_dict["response_type"] == "code"
    assert "redirect_uri" in query_dict
    assert query_dict["redirect_uri"] == redirect_uri
    assert "code_challenge_method" in query_dict
    assert query_dict["code_challenge_method"] == "S256"
    assert "scope" in query_dict
    assert query_dict["scope"] == scope
    assert "state" in query_dict
    assert "code_challenge" in query_dict

    # check a login_data has been registered in user session
    assert "login_data" in request.session
    login_data = request.session["login_data"]
    assert "code_verifier" in login_data
    assert "state" in login_data
    assert "redirect_uri" in login_data
    assert login_data["redirect_uri"] == query_dict["redirect_uri"]
    return login_data


@pytest.mark.django_db
def test_oidc_login_views_success(client, keycloak_oidc):
    """
    Simulate a successful login authentication with OpenID Connect
    authorization code flow with PKCE.
    """
    # user initiates login process
    login_url = reverse("oidc-login")

    # should redirect to Keycloak authentication page in order
    # for a user to login with its username / password
    response = client.get(login_url)
    assert response.status_code == 302

    request = response.wsgi_request
    assert isinstance(request.user, AnonymousUser)

    login_data = _check_oidc_login_code_flow_data(
        request,
        response,
        keycloak_oidc,
        redirect_uri=reverse("oidc-login-complete", request=request),
    )

    # once a user has identified himself in Keycloak, he is
    # redirected to the 'oidc-login-complete' view to
    # login in Django.

    # generate authorization code / session state in the same
    # manner as Keycloak
    code = f"{str(uuid.uuid4())}.{str(uuid.uuid4())}.{str(uuid.uuid4())}"
    session_state = str(uuid.uuid4())

    login_complete_url = reverse(
        "oidc-login-complete",
        query_params={
            "code": code,
            "state": login_data["state"],
            "session_state": session_state,
        },
    )

    # login process finalization, should redirect to root url by default
    response = client.get(login_complete_url)
    assert response.status_code == 302

    request = response.wsgi_request
    assert response["location"] == request.build_absolute_uri("/")

    # user should be authenticated
    assert isinstance(request.user, OIDCUser)

    # check remote user has not been saved to Django database
    with pytest.raises(User.DoesNotExist):
        User.objects.get(username=request.user.username)


@pytest.mark.django_db
def test_oidc_logout_view_success(client, keycloak_oidc):
    """
    Simulate a successful logout operation with OpenID Connect.
    """
    # login our test user
    client.login(code="", code_verifier="", redirect_uri="")
    keycloak_oidc.authorization_code.assert_called()

    # user initiates logout
    next_path = reverse("root")
    oidc_logout_url = reverse("oidc-logout", query_params={"next_path": next_path})

    # should redirect to logout page
    response = client.get(oidc_logout_url)
    assert response.status_code == 302

    request = response.wsgi_request
    assert response["location"] == next_path

    # should have been logged out in Keycloak
    oidc_profile = keycloak_oidc.login()
    keycloak_oidc.logout.assert_called_with(oidc_profile["refresh_token"])

    # check effective logout in Django
    assert isinstance(request.user, AnonymousUser)


@pytest.mark.django_db
def test_oidc_login_view_failure(client, keycloak_oidc):
    """
    Simulate a failed authentication with OpenID Connect.
    """
    keycloak_oidc.set_auth_success(False)

    # user initiates login process
    login_url = reverse("oidc-login")
    # should render an error page
    response = client.get(login_url)
    assert response.status_code == 500
    request = response.wsgi_request

    # no users should be logged in
    assert isinstance(request.user, AnonymousUser)


# Simulate possible errors with OpenID Connect in the login complete view.


def test_oidc_login_complete_view_no_login_data(client):
    # user initiates login process
    login_url = reverse("oidc-login-complete")
    # should return with error
    response = client.get(login_url)
    assert response.status_code == 500

    assert_contains(
        response, "Login process has not been initialized.", status_code=500
    )


def test_oidc_login_complete_view_missing_parameters(client):
    # simulate login process has been initialized
    session = client.session
    session["login_data"] = {
        "code_verifier": "",
        "state": str(uuid.uuid4()),
        "redirect_uri": "",
        "next_path": "",
    }
    session.save()

    # user initiates login process
    login_url = reverse("oidc-login-complete")

    # should return with error
    response = client.get(login_url)
    assert response.status_code == 400
    request = response.wsgi_request
    assert_contains(
        response, "Missing query parameters for authentication.", status_code=400
    )

    # no user should be logged in
    assert isinstance(request.user, AnonymousUser)


def test_oidc_login_complete_wrong_csrf_token(client, keycloak_oidc):
    # simulate login process has been initialized
    session = client.session
    session["login_data"] = {
        "code_verifier": "",
        "state": str(uuid.uuid4()),
        "redirect_uri": "",
        "next_path": "",
    }
    session.save()

    # user initiates login process
    login_url = reverse(
        "oidc-login-complete", query_params={"code": "some-code", "state": "some-state"}
    )

    # should render an error page
    response = client.get(login_url)
    assert response.status_code == 400
    request = response.wsgi_request
    assert_contains(
        response, "Wrong CSRF token, aborting login process.", status_code=400
    )

    # no user should be logged in
    assert isinstance(request.user, AnonymousUser)


@pytest.mark.django_db
def test_oidc_login_complete_wrong_code_verifier(client, keycloak_oidc):
    keycloak_oidc.set_auth_success(False)

    # simulate login process has been initialized
    session = client.session
    session["login_data"] = {
        "code_verifier": "",
        "state": str(uuid.uuid4()),
        "redirect_uri": "",
        "next_path": "",
    }
    session.save()

    # check authentication error is reported
    login_url = reverse(
        "oidc-login-complete",
        query_params={"code": "some-code", "state": session["login_data"]["state"]},
    )

    # should render an error page
    response = client.get(login_url)
    assert response.status_code == 500

    request = response.wsgi_request
    assert_contains(response, "User authentication failed.", status_code=500)

    # no user should be logged in
    assert isinstance(request.user, AnonymousUser)


@pytest.mark.django_db
def test_oidc_logout_view_failure(client, keycloak_oidc):
    """
    Simulate a failed logout operation with OpenID Connect.
    """
    # login our test user
    client.login(code="", code_verifier="", redirect_uri="")

    error = "unknown_error"
    error_message = json.dumps({"error": error}).encode()
    keycloak_oidc.logout.side_effect = KeycloakError(
        error_message=error_message, response_code=401
    )

    # user initiates logout process
    logout_url = reverse("oidc-logout")

    # should return with error
    response = client.get(logout_url)
    assert response.status_code == 500
    request = response.wsgi_request
    assert_contains(response, error, status_code=500)

    # user should be logged out from Django anyway
    assert isinstance(request.user, AnonymousUser)
