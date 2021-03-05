# Copyright (C) 2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from copy import copy
from urllib.parse import parse_qs, urlparse

from keycloak.exceptions import KeycloakError
import pytest

from swh.auth.pytest_plugin import keycloak_mock_factory
from swh.auth.tests.sample_data import (
    CLIENT_ID,
    DECODED_TOKEN,
    OIDC_PROFILE,
    REALM_NAME,
    SERVER_URL,
    USER_INFO,
)

# Make keycloak fixture to use for tests below.
keycloak_mock = keycloak_mock_factory(
    server_url=SERVER_URL, realm_name=REALM_NAME, client_id=CLIENT_ID,
)


def test_keycloak_well_known(keycloak_mock):
    well_known_result = keycloak_mock.well_known()
    assert set(well_known_result.keys()) == {
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "end_session_endpoint",
        "jwks_uri",
        "token_introspection_endpoint",
    }


def test_keycloak_authorization_url(keycloak_mock):
    actual_auth_uri = keycloak_mock.authorization_url("http://redirect-uri", foo="bar")

    expected_auth_url = keycloak_mock.well_known()["authorization_endpoint"]
    parsed_result = urlparse(actual_auth_uri)
    assert expected_auth_url.endswith(parsed_result.path)

    parsed_query = parse_qs(parsed_result.query)
    assert parsed_query == {
        "client_id": [CLIENT_ID],
        "response_type": ["code"],
        "redirect_uri": ["http://redirect-uri"],
        "foo": ["bar"],
    }


def test_keycloak_authorization_code_fail(keycloak_mock):
    "Authorization failure raise error"
    # Simulate failed authentication with Keycloak
    keycloak_mock.set_auth_success(False)

    with pytest.raises(KeycloakError):
        keycloak_mock.authorization_code("auth-code", "redirect-uri")


def test_keycloak_authorization_code(keycloak_mock):
    actual_response = keycloak_mock.authorization_code("auth-code", "redirect-uri")
    assert actual_response == OIDC_PROFILE


def test_keycloak_refresh_token(keycloak_mock):
    actual_result = keycloak_mock.refresh_token("refresh-token")
    assert actual_result == OIDC_PROFILE


def test_keycloak_userinfo(keycloak_mock):
    actual_user_info = keycloak_mock.userinfo("refresh-token")
    assert actual_user_info == USER_INFO


def test_keycloak_logout(keycloak_mock):
    """Login out does not raise"""
    keycloak_mock.logout("refresh-token")


def test_keycloak_decode_token(keycloak_mock):
    actual_decoded_data = keycloak_mock.decode_token(OIDC_PROFILE["access_token"])

    actual_decoded_data2 = copy(actual_decoded_data)
    expected_decoded_token = copy(DECODED_TOKEN)
    for dynamic_valued_key in ["exp", "auth_time"]:
        actual_decoded_data2.pop(dynamic_valued_key)
        expected_decoded_token.pop(dynamic_valued_key)

    assert actual_decoded_data2 == expected_decoded_token


def test_keycloak_login(keycloak_mock):
    actual_response = keycloak_mock.login("username", "password")
    assert actual_response == OIDC_PROFILE
