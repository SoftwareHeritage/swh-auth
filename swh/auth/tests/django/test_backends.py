# Copyright (C) 2020-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from datetime import datetime, timedelta
from unittest.mock import Mock

from django.conf import settings
from django.contrib.auth import authenticate, get_backends
import pytest
from rest_framework.exceptions import AuthenticationFailed

from swh.auth.django.backends import OIDCBearerTokenAuthentication
from swh.auth.django.models import OIDCUser
from swh.auth.django.utils import reverse
from swh.auth.keycloak import ExpiredSignatureError


def _authenticate_user(request_factory):
    request = request_factory.get(reverse("root"))

    return authenticate(
        request=request,
        code="some-code",
        code_verifier="some-code-verifier",
        redirect_uri="https://localhost:5004",
    )


def _check_authenticated_user(user, decoded_token, keycloak_oidc):
    assert user is not None
    assert isinstance(user, OIDCUser)
    assert user.id != 0
    assert user.username == decoded_token["preferred_username"]
    assert user.password == ""
    assert user.first_name == decoded_token["given_name"]
    assert user.last_name == decoded_token["family_name"]
    assert user.email == decoded_token["email"]
    assert user.is_staff == ("/staff" in decoded_token["groups"])
    assert user.sub == decoded_token["sub"]
    resource_access = decoded_token.get("resource_access", {})
    resource_access_client = resource_access.get(keycloak_oidc.client_id, {})
    assert user.permissions == set(resource_access_client.get("roles", []))


@pytest.mark.django_db
def test_oidc_code_pkce_auth_backend_success(keycloak_oidc, request_factory):
    """
    Checks successful login based on OpenID Connect with PKCE extension
    Django authentication backend (login from Web UI).
    """
    keycloak_oidc.user_groups = ["/staff"]

    oidc_profile = keycloak_oidc.login()
    user = _authenticate_user(request_factory)

    decoded_token = keycloak_oidc.decode_token(user.access_token)
    _check_authenticated_user(user, decoded_token, keycloak_oidc)

    auth_datetime = datetime.fromtimestamp(decoded_token["iat"])
    exp_datetime = datetime.fromtimestamp(decoded_token["exp"])
    refresh_exp_datetime = auth_datetime + timedelta(
        seconds=oidc_profile["refresh_expires_in"]
    )

    assert user.access_token == oidc_profile["access_token"]
    assert user.expires_at == exp_datetime
    assert user.id_token == oidc_profile["id_token"]
    assert user.refresh_token == oidc_profile["refresh_token"]
    assert user.refresh_expires_at == refresh_exp_datetime
    assert user.scope == oidc_profile["scope"]
    assert user.session_state == oidc_profile["session_state"]

    backend_path = "swh.auth.django.backends.OIDCAuthorizationCodePKCEBackend"
    assert user.backend == backend_path
    backend_idx = settings.AUTHENTICATION_BACKENDS.index(backend_path)
    assert get_backends()[backend_idx].get_user(user.id) == user


@pytest.mark.django_db
def test_oidc_code_pkce_auth_backend_failure(keycloak_oidc, request_factory):
    """
    Checks failed login based on OpenID Connect with PKCE extension Django
    authentication backend (login from Web UI).
    """
    keycloak_oidc.set_auth_success(False)

    user = _authenticate_user(request_factory)

    assert user is None


@pytest.mark.django_db
def test_oidc_code_pkce_auth_backend_refresh_token_success(
    keycloak_oidc, request_factory
):
    """
    Checks access token renewal success using refresh token.
    """

    oidc_profile = keycloak_oidc.login()
    decoded_token = keycloak_oidc.decode_token(oidc_profile["access_token"])

    keycloak_oidc.decode_token = Mock()
    keycloak_oidc.decode_token.side_effect = [
        ExpiredSignatureError("access token token has expired"),
        decoded_token,
    ]

    user = _authenticate_user(request_factory)

    oidc_profile = keycloak_oidc.login()
    keycloak_oidc.refresh_token.assert_called_with(oidc_profile["refresh_token"])

    assert user is not None


@pytest.mark.django_db
def test_oidc_code_pkce_auth_backend_refresh_token_failure(
    keycloak_oidc, request_factory
):
    """
    Checks access token renewal failure using refresh token.
    """
    keycloak_oidc.decode_token = Mock()
    keycloak_oidc.decode_token.side_effect = ExpiredSignatureError(
        "access token token has expired"
    )
    keycloak_oidc.refresh_token.side_effect = Exception("OIDC session has expired")

    user = _authenticate_user(request_factory)

    oidc_profile = keycloak_oidc.login()
    keycloak_oidc.refresh_token.assert_called_with(oidc_profile["refresh_token"])

    assert user is None


@pytest.mark.django_db
def test_oidc_code_pkce_auth_backend_permissions(keycloak_oidc, request_factory):
    """
    Checks that a permission defined with OpenID Connect is correctly mapped
    to a Django one when logging from Web UI.
    """
    realm_permission = "swh.some-permission"
    client_permission = "webapp.some-permission"
    keycloak_oidc.realm_permissions = [realm_permission]
    keycloak_oidc.client_permissions = [client_permission]
    user = _authenticate_user(request_factory)
    assert user.has_perm(realm_permission)
    assert user.has_perm(client_permission)
    assert user.get_all_permissions() == {realm_permission, client_permission}
    assert user.get_group_permissions() == {realm_permission, client_permission}
    assert user.has_module_perms("webapp")
    assert not user.has_module_perms("foo")


@pytest.mark.django_db
def test_drf_oidc_bearer_token_auth_backend_success(keycloak_oidc, api_request_factory):
    """
    Checks successful login based on OpenID Connect bearer token Django REST
    Framework authentication backend (Web API login).
    """
    url = reverse("api-test")
    drf_auth_backend = OIDCBearerTokenAuthentication()

    oidc_profile = keycloak_oidc.login()
    refresh_token = oidc_profile["refresh_token"]
    access_token = oidc_profile["access_token"]

    decoded_token = keycloak_oidc.decode_token(access_token)

    request = api_request_factory.get(url, HTTP_AUTHORIZATION=f"Bearer {refresh_token}")

    user, _ = drf_auth_backend.authenticate(request)
    _check_authenticated_user(user, decoded_token, keycloak_oidc)
    # oidc_profile is not filled when authenticating through bearer token
    assert hasattr(user, "access_token") and user.access_token is None


@pytest.mark.django_db
def test_drf_oidc_bearer_token_auth_backend_failure(keycloak_oidc, api_request_factory):
    """
    Checks failed login based on OpenID Connect bearer token Django REST
    Framework authentication backend (Web API login).
    """
    url = reverse("api-test")
    drf_auth_backend = OIDCBearerTokenAuthentication()

    oidc_profile = keycloak_oidc.login()

    # simulate a failed authentication with a bearer token in expected format
    keycloak_oidc.set_auth_success(False)

    refresh_token = oidc_profile["refresh_token"]

    request = api_request_factory.get(url, HTTP_AUTHORIZATION=f"Bearer {refresh_token}")

    with pytest.raises(AuthenticationFailed):
        drf_auth_backend.authenticate(request)

    # simulate a failed authentication with an invalid bearer token format
    request = api_request_factory.get(
        url, HTTP_AUTHORIZATION="Bearer invalid-token-format"
    )

    with pytest.raises(AuthenticationFailed):
        drf_auth_backend.authenticate(request)


def test_drf_oidc_auth_invalid_or_missing_auth_type(keycloak_oidc, api_request_factory):
    """
    Checks failed login based on OpenID Connect bearer token Django REST
    Framework authentication backend (Web API login) due to invalid
    authorization header value.
    """
    url = reverse("api-test")
    drf_auth_backend = OIDCBearerTokenAuthentication()

    oidc_profile = keycloak_oidc.login()
    refresh_token = oidc_profile["refresh_token"]

    # Invalid authorization type
    request = api_request_factory.get(url, HTTP_AUTHORIZATION="Foo token")

    with pytest.raises(AuthenticationFailed):
        drf_auth_backend.authenticate(request)

    # Missing authorization type
    request = api_request_factory.get(url, HTTP_AUTHORIZATION=f"{refresh_token}")

    with pytest.raises(AuthenticationFailed):
        drf_auth_backend.authenticate(request)


@pytest.mark.django_db
def test_drf_oidc_bearer_token_auth_backend_permissions(
    keycloak_oidc, api_request_factory
):
    """
    Checks that a permission defined with OpenID Connect is correctly mapped
    to a Django one when using bearer token authentication.
    """
    realm_permission = "swh.some-permission"
    client_permission = "webapp.some-permission"
    keycloak_oidc.realm_permissions = [realm_permission]
    keycloak_oidc.client_permissions = [client_permission]

    drf_auth_backend = OIDCBearerTokenAuthentication()
    oidc_profile = keycloak_oidc.login()
    refresh_token = oidc_profile["refresh_token"]
    url = reverse("api-test")
    request = api_request_factory.get(url, HTTP_AUTHORIZATION=f"Bearer {refresh_token}")
    user, _ = drf_auth_backend.authenticate(request)

    assert user.has_perm(realm_permission)
    assert user.has_perm(client_permission)
    assert user.get_all_permissions() == {realm_permission, client_permission}
    assert user.get_group_permissions() == {realm_permission, client_permission}
    assert user.has_module_perms("webapp")
    assert not user.has_module_perms("foo")
