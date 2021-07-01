# Copyright (C) 2020-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from click.testing import CliRunner
import pytest

from swh.auth.cli import auth
from swh.auth.tests.sample_data import OIDC_PROFILE

runner = CliRunner()


@pytest.fixture()
def keycloak_oidc(keycloak_oidc, mocker):
    def _keycloak_oidc(server_url, realm_name, client_id):
        keycloak_oidc.server_url = server_url
        keycloak_oidc.realm_name = realm_name
        keycloak_oidc.client_id = client_id
        return keycloak_oidc

    keycloak_oidc_client = mocker.patch("swh.auth.keycloak.KeycloakOpenIDConnect")
    keycloak_oidc_client.side_effect = _keycloak_oidc
    return keycloak_oidc


def _run_auth_command(command, keycloak_oidc, input=None):
    server_url = "http://localhost:5080/auth"
    realm_name = "realm-test"
    client_id = "client-test"
    result = runner.invoke(
        auth,
        [
            "--oidc-server-url",
            server_url,
            "--realm-name",
            realm_name,
            "--client-id",
            client_id,
            *command,
        ],
        input=input,
    )
    assert keycloak_oidc.server_url == server_url
    assert keycloak_oidc.realm_name == realm_name
    assert keycloak_oidc.client_id == client_id
    return result


@pytest.fixture
def user_credentials():
    return {"username": "foo", "password": "bar"}


def test_auth_generate_token_ok(keycloak_oidc, mocker, user_credentials):
    mock_getpass = mocker.patch("getpass.getpass")
    mock_getpass.return_value = user_credentials["password"]

    command = ["generate-token", user_credentials["username"]]
    result = _run_auth_command(
        command, keycloak_oidc, input=f"{user_credentials['password']}\n"
    )
    assert result.exit_code == 0
    assert result.output[:-1] == OIDC_PROFILE["refresh_token"]


def test_auth_generate_token_error(keycloak_oidc, mocker, user_credentials):
    keycloak_oidc.set_auth_success(False)
    mock_getpass = mocker.patch("getpass.getpass")
    mock_getpass.return_value = user_credentials["password"]

    command = ["generate-token", user_credentials["username"]]
    result = _run_auth_command(
        command, keycloak_oidc, input=f"{user_credentials['password']}\n"
    )
    assert result.exit_code == 1
    assert result.output[:-1] == "invalid_grant: Invalid user credentials"


def test_auth_remove_token_ok(keycloak_oidc):
    command = ["revoke-token", OIDC_PROFILE["refresh_token"]]
    result = _run_auth_command(command, keycloak_oidc)
    assert result.exit_code == 0
    assert result.output[:-1] == "Token successfully revoked."


def test_auth_remove_token_error(keycloak_oidc):
    keycloak_oidc.set_auth_success(False)
    command = ["revoke-token", OIDC_PROFILE["refresh_token"]]
    result = _run_auth_command(command, keycloak_oidc)
    assert result.exit_code == 1
    assert result.output[:-1] == "invalid_grant: Invalid user credentials"
