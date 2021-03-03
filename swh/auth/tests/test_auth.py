# Copyright (C) 2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from urllib.parse import parse_qs, urlparse

from keycloak.exceptions import KeycloakAuthenticationError, KeycloakConnectionError
import pytest

from .sample_data import OIDC_PROFILE, USER_INFO, WELL_KNOWN


def test_auth_connection_failure(keycloak_open_id_connect):
    with pytest.raises(KeycloakConnectionError):
        keycloak_open_id_connect.well_known()


def test_auth_well_known(mock_keycloak, keycloak_open_id_connect):
    well_known_result = keycloak_open_id_connect.well_known()
    assert well_known_result is not None
    assert well_known_result == WELL_KNOWN

    assert mock_keycloak.called


def test_auth_authorization_url(mock_keycloak, keycloak_open_id_connect):
    actual_auth_uri = keycloak_open_id_connect.authorization_url(
        "http://redirect-uri", foo="bar"
    )

    expected_auth_url = WELL_KNOWN["authorization_endpoint"]
    parsed_result = urlparse(actual_auth_uri)
    assert expected_auth_url.endswith(parsed_result.path)

    parsed_query = parse_qs(parsed_result.query)
    assert parsed_query == {
        "client_id": ["client-id"],
        "response_type": ["code"],
        "redirect_uri": ["http://redirect-uri"],
        "foo": ["bar"],
    }

    assert mock_keycloak.called


def test_auth_authorization_code_fail(
    mock_keycloak_refused_auth, keycloak_open_id_connect
):
    with pytest.raises(KeycloakAuthenticationError):
        keycloak_open_id_connect.authorization_code("auth-code", "redirect-uri")

    assert mock_keycloak_refused_auth.called


def test_auth_authorization_code(mock_keycloak, keycloak_open_id_connect):
    actual_response = keycloak_open_id_connect.authorization_code(
        "auth-code", "redirect-uri"
    )

    assert actual_response == OIDC_PROFILE

    assert mock_keycloak.called


def test_auth_refresh_token(mock_keycloak, keycloak_open_id_connect):
    actual_result = keycloak_open_id_connect.refresh_token("refresh-token")
    assert actual_result is not None

    assert mock_keycloak.called


def test_auth_userinfo(mock_keycloak, keycloak_open_id_connect):
    actual_user_info = keycloak_open_id_connect.userinfo("refresh-token")
    assert actual_user_info == USER_INFO

    assert mock_keycloak.called
