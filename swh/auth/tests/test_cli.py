# Copyright (C) 2020-2026  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from urllib.parse import urlparse

from click.testing import CliRunner
import pytest
import yaml

from swh.auth.cli import DEFAULT_CONFIG, auth
from swh.auth.tests.sample_data import OIDC_PROFILE, USER_INFO

runner = CliRunner()


@pytest.fixture
def config_file(monkeypatch, tmp_path):
    # Set Swh global config file to a temp directory
    cfg_file = tmp_path / "global.yml"
    monkeypatch.setenv("SWH_CONFIG_FILENAME", str(cfg_file))
    return cfg_file


@pytest.fixture()
def keycloak_oidc(keycloak_oidc, mocker):
    def _keycloak_oidc_from_config(keycloak):
        keycloak_oidc.update_keycloak_configuration(
            keycloak["server_url"], keycloak["realm_name"]
        )
        keycloak_oidc.client_id = keycloak["client_id"]
        return keycloak_oidc

    keycloak_oidc_client_from_config = mocker.patch(
        "swh.auth.keycloak.KeycloakOpenIDConnect.from_config"
    )
    keycloak_oidc_client_from_config.side_effect = _keycloak_oidc_from_config
    return keycloak_oidc


def _run_auth_command(command, keycloak_oidc, input=None):
    result = runner.invoke(
        auth,
        [
            "--oidc-server-url",
            keycloak_oidc.server_url,
            "--realm-name",
            keycloak_oidc.realm_name,
            "--client-id",
            keycloak_oidc.client_id,
            *command,
        ],
        input=input,
    )
    return result


@pytest.fixture
def user_credentials():
    return {"username": "foo", "password": "bar"}


def mock_auth_requests(keycloak_oidc, requests_mock, kc_login_page, login_action_url):
    redirect_uri = "https://archive.softwareheritage.org/"
    code = "some-code"
    login_url = keycloak_oidc.authorization_url(redirect_uri=redirect_uri)
    login_url_parsed = urlparse(login_url)
    login_url_no_params = (
        f"{login_url_parsed.scheme}://{login_url_parsed.netloc}{login_url_parsed.path}"
    )
    requests_mock.get(login_url_no_params, text=kc_login_page)
    requests_mock.post(
        login_action_url,
        status_code=302,
        headers={"Location": f"{redirect_uri}?code={code}"},
    )


def test_auth_generate_token_ok(
    keycloak_oidc,
    mocker,
    user_credentials,
    requests_mock,
    kc_login_page,
    login_action_url,
):
    mock_getpass = mocker.patch("getpass.getpass")
    mock_getpass.return_value = user_credentials["password"]

    mock_auth_requests(keycloak_oidc, requests_mock, kc_login_page, login_action_url)

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
    assert result.exit_code != 0
    assert "invalid_grant: Invalid user credentials" in result.output


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


def test_auth_generate_token_no_password_prompt_ok(
    keycloak_oidc, user_credentials, requests_mock, kc_login_page, login_action_url
):
    mock_auth_requests(keycloak_oidc, requests_mock, kc_login_page, login_action_url)
    command = [
        "generate-token",
        user_credentials["username"],
        "--password",
        user_credentials["password"],
    ]
    result = _run_auth_command(command, keycloak_oidc)
    assert result.exit_code == 0
    assert result.output[:-1] == OIDC_PROFILE["refresh_token"]


def test_auth_config_no_options_no_save_ok(
    keycloak_oidc,
    mocker,
    user_credentials,
    config_file,
    requests_mock,
    kc_login_page,
    login_action_url,
):
    """Test `auth config` default command (without options).
    Prompt answer 'no' to save config file question.

        swh auth config

    """
    mock_getpass = mocker.patch("getpass.getpass")
    mock_getpass.return_value = user_credentials["password"]

    mock_auth_requests(keycloak_oidc, requests_mock, kc_login_page, login_action_url)

    command = ["config"]
    result = _run_auth_command(
        command,
        keycloak_oidc,
        input=f"{user_credentials['username']}\nno\n",
    )

    assert result.exit_code == 0
    assert (
        f"A new token will be generated for realm '{keycloak_oidc.realm_name}'"
        f" and client '{keycloak_oidc.client_id}'" in result.output
    )
    assert (
        f"Token generation success for username {user_credentials['username']}"
        in result.output
    )
    assert (
        f"Token verification success for username {user_credentials['username']}"
        in result.output
    )
    assert (
        f"Authentication configuration file {config_file} written successfully"
        not in result.output
    )


def test_auth_config_no_options_save_ok(
    keycloak_oidc,
    mocker,
    user_credentials,
    config_file,
    requests_mock,
    kc_login_page,
    login_action_url,
):
    """Test `auth config` default command (without options).
    Prompt answer 'yes' to save config file question.

        swh auth config

    """
    mock_getpass = mocker.patch("getpass.getpass")
    mock_getpass.return_value = user_credentials["password"]

    mock_auth_requests(keycloak_oidc, requests_mock, kc_login_page, login_action_url)

    command = ["config"]
    result = _run_auth_command(
        command,
        keycloak_oidc,
        input=f"{user_credentials['username']}\nyes\n",
    )

    assert result.exit_code == 0
    assert (
        f"A new token will be generated for realm '{keycloak_oidc.realm_name}'"
        f" and client '{keycloak_oidc.client_id}'" in result.output
    )
    assert (
        f"Token generation success for username {user_credentials['username']}"
        in result.output
    )
    assert (
        f"Token verification success for username {user_credentials['username']}"
        in result.output
    )
    assert (
        f"Authentication configuration file {config_file} written successfully"
        in result.output
    )

    # Check config saved to file
    expected_cfg = f"""
    keycloak:
      client_id: {keycloak_oidc.client_id}
      realm_name: {keycloak_oidc.realm_name}
      server_url: {keycloak_oidc.server_url}
    keycloak_tokens:
      {keycloak_oidc.realm_name}:
        {keycloak_oidc.client_id}: {OIDC_PROFILE["refresh_token"]}
    """
    expected_cfg = yaml.safe_load(expected_cfg)
    results = yaml.safe_load(config_file.read_text())

    assert results == expected_cfg


def test_auth_config_invalid_username_error(
    keycloak_oidc, mocker, user_credentials, config_file
):
    """Test `auth config` default command (without options) with invalid username.

    swh auth config

    """
    keycloak_oidc.set_auth_success(False)
    mock_getpass = mocker.patch("getpass.getpass")
    mock_getpass.return_value = user_credentials["password"]

    command = ["config"]
    result = _run_auth_command(
        command,
        keycloak_oidc,
        input="invalidusername\nno\n",
    )

    assert result.exit_code != 0
    assert (
        f"A new token will be generated for realm '{keycloak_oidc.realm_name}'"
        f" and client '{keycloak_oidc.client_id}'" in result.output
    )
    assert ("Error: invalid_grant: Invalid user credentials") in result.output


def test_auth_config_invalid_password_error(
    keycloak_oidc, mocker, user_credentials, config_file
):
    """Test `auth config` default command with invalid password.

    swh auth config

    """
    keycloak_oidc.set_auth_success(False)
    mock_getpass = mocker.patch("getpass.getpass")
    mock_getpass.return_value = "invalid_password"

    command = ["config"]
    result = _run_auth_command(
        command,
        keycloak_oidc,
        input=f"{user_credentials['username']}\nno\n",
    )

    assert result.exit_code != 0
    assert (
        f"A new token will be generated for realm '{keycloak_oidc.realm_name}'"
        f" and client '{keycloak_oidc.client_id}'" in result.output
    )
    assert ("Error: invalid_grant: Invalid user credentials") in result.output


def test_auth_client_id_config_no_options_save_ok(
    keycloak_oidc,
    mocker,
    user_credentials,
    config_file,
    requests_mock,
    kc_login_page,
    login_action_url,
):
    """Test `auth --client-id myclientid config` command (Client ID option of auth).
    Prompt answer 'yes' to save config file question.

        swh auth --client-id myclientid config

    """
    mock_getpass = mocker.patch("getpass.getpass")
    mock_getpass.return_value = user_credentials["password"]

    client_id = "myclientid"
    default_kc_config = DEFAULT_CONFIG["keycloak"]
    keycloak_oidc.update_keycloak_configuration(
        default_kc_config["server_url"], default_kc_config["realm_name"]
    )
    keycloak_oidc.client_id = client_id

    mock_auth_requests(keycloak_oidc, requests_mock, kc_login_page, login_action_url)

    command = ["config"]
    result = runner.invoke(
        auth,
        [
            "--client-id",
            client_id,
            *command,
        ],
        input=f"{user_credentials['username']}\nyes\n",
    )

    assert result.exit_code == 0
    assert client_id in result.output
    assert keycloak_oidc.client_id == client_id

    # Check config saved to file
    expected_cfg = f"""
    keycloak:
      client_id: {client_id}
      realm_name: {keycloak_oidc.realm_name}
      server_url: {keycloak_oidc.server_url}
    keycloak_tokens:
      {keycloak_oidc.realm_name}:
        {keycloak_oidc.client_id}: {OIDC_PROFILE["refresh_token"]}
    """
    expected_cfg = yaml.safe_load(expected_cfg)
    results = yaml.safe_load(config_file.read_text())

    assert results == expected_cfg


def test_auth_config_file_config_ok(
    keycloak_oidc, mocker, user_credentials, config_file
):
    """Test `auth --config-file myconfigfile.yml config` command (Configuration file
    option of auth).

        swh auth --config-file myconfigfile.yml config

    """
    # Create a valid configuration file
    expected_cfg = f"""
    keycloak:
      client_id: {keycloak_oidc.client_id}
      realm_name: {keycloak_oidc.realm_name}
      server_url: {keycloak_oidc.server_url}
    keycloak_tokens:
      {keycloak_oidc.realm_name}:
        {keycloak_oidc.client_id}: {OIDC_PROFILE["refresh_token"]}
    """
    config_file.write_text(expected_cfg)

    command = ["config"]
    result = runner.invoke(
        auth,
        [
            "--config-file",
            str(config_file),
            *command,
        ],
        input="verify\nn",
    )

    assert result.exit_code == 0
    assert (
        f"A token was found in {str(config_file)} for realm '{keycloak_oidc.realm_name}'"
        f" and client '{keycloak_oidc.client_id}'" in result.output
    )
    assert "Would you like to verify the token or generate a new one?" in result.output
    assert (
        f"Token verification success for username {USER_INFO['preferred_username']}"
        in result.output
    )


def test_auth_config_username_ok(
    keycloak_oidc,
    mocker,
    user_credentials,
    config_file,
    requests_mock,
    kc_login_page,
    login_action_url,
):
    """Test `auth config` command with `--username` option.

    swh auth config --username foo

    """
    mock_getpass = mocker.patch("getpass.getpass")
    mock_getpass.return_value = user_credentials["password"]

    mock_auth_requests(keycloak_oidc, requests_mock, kc_login_page, login_action_url)

    command = ["config", "--username", user_credentials["username"]]
    result = _run_auth_command(
        command,
        keycloak_oidc,
        input="no\n",
    )

    assert result.exit_code == 0
    assert (
        f"Token verification success for username {user_credentials['username']}"
        in result.output
    )


def test_auth_config_token_ok(keycloak_oidc, mocker, user_credentials, config_file):
    """Test `auth config` command with `--token` option.

    swh auth config --token myvalidtoken

    """
    mock_getpass = mocker.patch("getpass.getpass")
    mock_getpass.return_value = user_credentials["password"]

    command = ["config", "--token", OIDC_PROFILE["refresh_token"]]
    result = _run_auth_command(
        command,
        keycloak_oidc,
        "verify\nn",
    )
    assert result.exit_code == 0
    assert "Would you like to verify the token or generate a new one?" in result.output
    assert (
        f"Token verification success for username {USER_INFO['preferred_username']}"
        in result.output
    )


def test_auth_config_username_and_token_ok(
    keycloak_oidc, mocker, user_credentials, config_file
):
    """Test `auth config` command with `--username` and `--token` options.

    swh auth config --username foo --token myvalidtoken

    """
    mock_getpass = mocker.patch("getpass.getpass")
    mock_getpass.return_value = user_credentials["password"]

    command = [
        "config",
        "--username",
        user_credentials["username"],
        "--token",
        OIDC_PROFILE["refresh_token"],
    ]
    result = _run_auth_command(
        command,
        keycloak_oidc,
        "verify\nn",
    )

    assert result.exit_code == 0
    assert "Would you like to verify the token or generate a new one?" in result.output
    assert (
        f"Token verification success for username {user_credentials['username']}"
        in result.output
    )
