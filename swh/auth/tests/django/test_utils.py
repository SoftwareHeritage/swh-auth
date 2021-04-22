# Copyright (C) 2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from copy import copy
from datetime import datetime

from django.test import override_settings
import pytest

from swh.auth.django.utils import (
    keycloak_oidc_client,
    oidc_user_from_decoded_token,
    oidc_user_from_profile,
)
from swh.auth.tests.sample_data import (
    CLIENT_ID,
    DECODED_TOKEN,
    OIDC_PROFILE,
    REALM_NAME,
    SERVER_URL,
)


def _check_user(user, is_staff=False, permissions=set()):
    assert user.id > 0
    assert user.username == DECODED_TOKEN["preferred_username"]
    assert user.password == ""
    assert user.first_name == DECODED_TOKEN["given_name"]
    assert user.last_name == DECODED_TOKEN["family_name"]
    assert user.email == DECODED_TOKEN["email"]
    assert user.is_staff == is_staff
    assert user.permissions == permissions
    assert user.sub == DECODED_TOKEN["sub"]

    date_now = datetime.now()
    if user.expires_at is not None:
        assert isinstance(user.expires_at, datetime)
        assert date_now <= user.expires_at
    if user.refresh_expires_at is not None:
        assert isinstance(user.refresh_expires_at, datetime)
        assert date_now <= user.refresh_expires_at

    assert user.oidc_profile == {
        k: getattr(user, k)
        for k in (
            "access_token",
            "expires_in",
            "expires_at",
            "id_token",
            "refresh_token",
            "refresh_expires_in",
            "refresh_expires_at",
            "scope",
            "session_state",
        )
    }


def test_oidc_user_from_decoded_token():
    user = oidc_user_from_decoded_token(DECODED_TOKEN)
    _check_user(user)


def test_oidc_user_with_permissions_from_decoded_token():
    decoded_token = copy(DECODED_TOKEN)
    decoded_token["groups"] = ["/staff", "api"]
    decoded_token["realm_access"] = {"roles": ["swh.ambassador"]}
    decoded_token["resource_access"] = {CLIENT_ID: {"roles": ["read-api"]}}

    user = oidc_user_from_decoded_token(decoded_token, client_id=CLIENT_ID)

    _check_user(user, is_staff=True, permissions={"swh.ambassador", "read-api"})


@pytest.mark.parametrize(
    "key,mapped_key",
    [
        ("preferred_username", "username"),
        ("given_name", "first_name"),
        ("family_name", "last_name"),
        ("email", "email"),
    ],
)
def test_oidc_user_from_decoded_token_empty_fields_ok(key, mapped_key):
    decoded_token = copy(DECODED_TOKEN)
    decoded_token.pop(key, None)

    user = oidc_user_from_decoded_token(decoded_token, client_id=CLIENT_ID)

    # Ensure the missing field is mapped to an empty value
    assert getattr(user, mapped_key) == ""


def test_oidc_user_from_profile(keycloak_oidc):
    user = oidc_user_from_profile(keycloak_oidc, OIDC_PROFILE)
    _check_user(user)


@override_settings(
    SWH_AUTH_SERVER_URL=None, SWH_AUTH_REALM_NAME=None, SWH_AUTH_CLIENT_ID=None,
)
def test_keycloak_oidc_client_missing_django_settings():

    with pytest.raises(ValueError, match="settings are mandatory"):
        keycloak_oidc_client()


@override_settings(
    SWH_AUTH_SERVER_URL=SERVER_URL,
    SWH_AUTH_REALM_NAME=REALM_NAME,
    SWH_AUTH_CLIENT_ID=CLIENT_ID,
)
def test_keycloak_oidc_client_parameters_from_django_settings():

    kc_oidc_client = keycloak_oidc_client()

    assert kc_oidc_client.server_url == SERVER_URL
    assert kc_oidc_client.realm_name == REALM_NAME
    assert kc_oidc_client.client_id == CLIENT_ID
