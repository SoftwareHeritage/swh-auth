# Copyright (C) 2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from copy import copy
import os
from urllib.parse import parse_qs, urlparse

from keycloak.exceptions import KeycloakError
import pytest
import yaml

from swh.auth.keycloak import KeycloakOpenIDConnect
from swh.auth.tests.sample_data import CLIENT_ID, DECODED_TOKEN, OIDC_PROFILE, USER_INFO
from swh.core.config import read


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

    with pytest.raises(KeycloakError):
        keycloak_mock.login("username", "password")


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
    for dynamic_valued_key in ["exp", "iat", "auth_time"]:
        actual_decoded_data2.pop(dynamic_valued_key, None)
        expected_decoded_token.pop(dynamic_valued_key, None)

    assert actual_decoded_data2 == expected_decoded_token


def test_keycloak_login(keycloak_mock):
    actual_response = keycloak_mock.login("username", "password")
    assert actual_response == OIDC_PROFILE


@pytest.fixture
def auth_config():
    return {
        "keycloak": {
            "server_url": "https://auth.swh.org/SWHTest",
            "realm_name": "SWHTest",
            "client_id": "client_id",
        }
    }


@pytest.fixture
def auth_config_path(tmp_path, monkeypatch, auth_config):
    conf_path = os.path.join(tmp_path, "auth.yml")
    with open(conf_path, "w") as f:
        f.write(yaml.dump(auth_config))
    monkeypatch.setenv("SWH_CONFIG_FILENAME", conf_path)
    return conf_path


def test_auth_KeycloakOpenIDConnect_from_config(auth_config):
    """Instantiating keycloak client out of configuration dict is possible

     """
    client = KeycloakOpenIDConnect.from_config(**auth_config)

    assert client.server_url == auth_config["keycloak"]["server_url"]
    assert client.realm_name == auth_config["keycloak"]["realm_name"]
    assert client.client_id == auth_config["keycloak"]["client_id"]


def test_auth_KeycloakOpenIDConnect_from_configfile(auth_config_path, monkeypatch):
    """Instantiating keycloak client out of environment variable is possible

     """
    client = KeycloakOpenIDConnect.from_configfile()

    auth_config = read(auth_config_path)

    assert client.server_url == auth_config["keycloak"]["server_url"]
    assert client.realm_name == auth_config["keycloak"]["realm_name"]
    assert client.client_id == auth_config["keycloak"]["client_id"]


def test_auth_KeycloakOpenIDConnect_from_configfile_override(
    auth_config_path, monkeypatch
):
    """Instantiating keycloak client out of environment variable is possible
    And caller can override the configuration  at calling

     """
    client = KeycloakOpenIDConnect.from_configfile(client_id="foobar")

    auth_config = read(auth_config_path)

    assert client.server_url == auth_config["keycloak"]["server_url"]
    assert client.realm_name == auth_config["keycloak"]["realm_name"]
    assert client.client_id == "foobar"
