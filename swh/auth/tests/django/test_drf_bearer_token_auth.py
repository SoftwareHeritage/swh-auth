# Copyright (C) 2020-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from django.contrib.auth.models import AnonymousUser, User
import pytest

from swh.auth.django.models import OIDCUser
from swh.auth.django.utils import reverse


@pytest.mark.django_db
def test_drf_django_session_auth_success(keycloak_oidc, client):
    """
    Check user gets authenticated when querying the web api
    through a web browser.
    """
    url = reverse("api-test")

    client.login(code="", code_verifier="", redirect_uri="")

    response = client.get(url)
    assert response.status_code == 200
    request = response.wsgi_request

    # user should be authenticated
    assert isinstance(request.user, OIDCUser)

    # check remoter used has not been saved to Django database
    with pytest.raises(User.DoesNotExist):
        User.objects.get(username=request.user.username)


@pytest.mark.django_db
def test_drf_oidc_bearer_token_auth_success(keycloak_oidc, api_client):
    """
    Check user gets authenticated when querying the web api
    through an HTTP client using bearer token authentication.
    """
    url = reverse("api-test")

    oidc_profile = keycloak_oidc.login()
    refresh_token = oidc_profile["refresh_token"]

    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh_token}")

    response = api_client.get(url)
    assert response.status_code == 200
    request = response.wsgi_request

    # user should be authenticated
    assert isinstance(request.user, OIDCUser)

    # check remoter used has not been saved to Django database
    with pytest.raises(User.DoesNotExist):
        User.objects.get(username=request.user.username)


@pytest.mark.django_db
def test_drf_oidc_bearer_token_auth_failure(keycloak_oidc, api_client):
    url = reverse("api-test")

    oidc_profile = keycloak_oidc.login()
    refresh_token = oidc_profile["refresh_token"]

    # check for failed authentication but with expected token format
    keycloak_oidc.set_auth_success(False)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh_token}")

    response = api_client.get(url)
    assert response.status_code == 403
    request = response.wsgi_request

    assert isinstance(request.user, AnonymousUser)

    # check for failed authentication when token format is invalid
    api_client.credentials(HTTP_AUTHORIZATION="Bearer invalid-token-format-ééàà")

    response = api_client.get(url)
    assert response.status_code == 400
    request = response.wsgi_request

    assert isinstance(request.user, AnonymousUser)


def test_drf_oidc_auth_invalid_or_missing_authorization_type(keycloak_oidc, api_client):
    url = reverse("api-test")

    oidc_profile = keycloak_oidc.login()
    refresh_token = oidc_profile["refresh_token"]

    # missing authorization type
    api_client.credentials(HTTP_AUTHORIZATION=f"{refresh_token}")

    response = api_client.get(url)
    assert response.status_code == 403
    request = response.wsgi_request

    assert isinstance(request.user, AnonymousUser)

    # invalid authorization type
    api_client.credentials(HTTP_AUTHORIZATION="Foo token")

    response = api_client.get(url)
    assert response.status_code == 403
    request = response.wsgi_request

    assert isinstance(request.user, AnonymousUser)
