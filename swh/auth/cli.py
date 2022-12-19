# Copyright (C) 2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

# WARNING: do not import unnecessary things here to keep cli startup time under
# control

import os
import sys
from typing import Any, Dict

import click
from click.core import Context

from swh.core.cli import swh as swh_cli_group

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

# TODO (T1410): All generic config code should reside in swh.core.config
DEFAULT_CONFIG_PATH = os.environ.get(
    "SWH_CONFIG_FILE", os.path.join(click.get_app_dir("swh"), "global.yml")
)

DEFAULT_CONFIG: Dict[str, Any] = {
    "oidc_server_url": "https://auth.softwareheritage.org/auth/",
    "realm_name": "SoftwareHeritage",
    "client_id": "swh-web",
    "bearer_token": None,
}


@swh_cli_group.group(name="auth", context_settings=CONTEXT_SETTINGS)
@click.option(
    "--oidc-server-url",
    "oidc_server_url",
    default=DEFAULT_CONFIG["oidc_server_url"],
    help=(
        "URL of OpenID Connect server (default to "
        '"https://auth.softwareheritage.org/auth/")'
    ),
)
@click.option(
    "--realm-name",
    "realm_name",
    default=DEFAULT_CONFIG["realm_name"],
    help=(
        "Name of the OpenID Connect authentication realm "
        '(default to "SoftwareHeritage")'
    ),
)
@click.option(
    "--client-id",
    "client_id",
    default=DEFAULT_CONFIG["client_id"],
    help=("OpenID Connect client identifier in the realm " '(default to "swh-web")'),
)
@click.option(
    "-C",
    "--config-file",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help=f"Configuration file (default: {DEFAULT_CONFIG_PATH})",
)
@click.pass_context
def auth(
    ctx: Context,
    oidc_server_url: str,
    realm_name: str,
    client_id: str,
    config_file: str,
):
    """
    Software Heritage Authentication tools.

    This CLI eases the retrieval of a bearer token to authenticate
    a user querying Software Heritage Web APIs.
    """
    import logging
    from pathlib import Path

    import yaml

    from swh.auth.keycloak import KeycloakOpenIDConnect
    from swh.core import config

    if not config_file:
        config_file = DEFAULT_CONFIG_PATH

    # Missing configuration file
    if not config.config_exists(config_file):
        # if not Path(config_file).exists():
        click.echo(f"The Swh configuration file {config_file} does not exists.")
        if click.confirm("Do you want to create it?"):
            Path(config_file).touch()
            Path(config_file).write_text("swh:\n")
            with open(config_file, "w") as file:
                yaml.dump({"swh": {"auth": DEFAULT_CONFIG}}, file)
                msg = f"Swh configuration file {config_file} successfully created."
            click.echo(click.style(msg, fg="green"))
        else:
            sys.exit(1)

    try:
        conf = config.read_raw_config(config.config_basepath(config_file))
        if not conf:
            raise ValueError(f"Cannot parse configuration file: {config_file}")
        assert conf["swh"]["auth"]
        conf = config.merge_configs(DEFAULT_CONFIG, conf["swh"]["auth"])
    except Exception:
        logging.warning(
            "Using default configuration (cannot load custom one)", exc_info=True
        )
        conf = DEFAULT_CONFIG

    ctx.ensure_object(dict)
    ctx.obj["oidc_client"] = KeycloakOpenIDConnect(
        oidc_server_url, realm_name, client_id
    )
    ctx.obj["config_file"] = config_file
    ctx.obj["config"] = conf


@auth.command("generate-token")
@click.argument("username")
@click.option(
    "--password",
    "-p",
    default=None,
    type=str,
    help="OpenID Connect client password in the realm",
)
@click.pass_context
def generate_token(ctx: Context, username: str, password):
    """
    Generate a new bearer token for a Web API authentication.

    Login with USERNAME, create a new OpenID Connect session and get
    bearer token.

    Users will be prompted for their password, then the token will be printed
    to standard output.

    The created OpenID Connect session is an offline one so the provided
    token has a much longer expiration time than classical OIDC
    sessions (usually several dozens of days).
    """
    from getpass import getpass

    from swh.auth.keycloak import KeycloakError, keycloak_error_message

    if not password:
        password = getpass()

    try:
        oidc_info = ctx.obj["oidc_client"].login(
            username, password, scope="openid offline_access"
        )
        print(oidc_info["refresh_token"])
    except KeycloakError as ke:
        print(keycloak_error_message(ke))
        sys.exit(1)


@auth.command("revoke-token")
@click.argument("token")
@click.pass_context
def revoke_token(ctx: Context, token: str):
    """
    Revoke a bearer token used for a Web API authentication.

    Use TOKEN to logout from an offline OpenID Connect session.

    The token is definitely revoked after that operation.
    """
    from swh.auth.keycloak import KeycloakError, keycloak_error_message

    try:
        ctx.obj["oidc_client"].logout(token)
        print("Token successfully revoked.")
    except KeycloakError as ke:
        print(keycloak_error_message(ke))
        sys.exit(1)


@auth.command("set-token")
@click.argument("token", required=False)
@click.pass_context
def set_token(ctx: Context, token: str):
    """
    Set a bearer token for an OIDC authentication.

    Users will be prompted for their token, then the token will be saved
    to standard configuration file.
    """
    from pathlib import Path

    import yaml

    from swh.auth.keycloak import KeycloakError, keycloak_error_message

    # Check if a token already exists in configuration file and inform the user
    if (
        "bearer_token" in ctx.obj["config"]
        and ctx.obj["config"]["bearer_token"] is not None
    ):
        if not click.confirm(
            "A token entry already exists in your configuration file."
            "\nDo you want to override it?"
        ):
            sys.exit(1)

    if not token:
        raw_token = click.prompt(text="Fill or Paste your token")
    else:
        raw_token = token

    bearer_token = raw_token.strip()

    # Ensure the token is valid by getting user info
    try:
        oidc_client = ctx.obj["oidc_client"]
        # userinfo endpoint needs the access_token
        access_token = oidc_client.refresh_token(refresh_token=bearer_token)[
            "access_token"
        ]
        oidc_info = oidc_client.userinfo(access_token=access_token)
        msg = (
            f"Token verification success for username {oidc_info['preferred_username']}"
        )
        click.echo(click.style(msg, fg="green"))
    except KeycloakError as ke:
        msg = keycloak_error_message(ke)
        click.echo(click.style(msg, fg="red"))
        ctx.exit(1)

    # Write the new token into the file.
    # TODO use ruamel.yaml to preserve comments in config file
    ctx.obj["config"]["bearer_token"] = bearer_token
    config_file_path = Path(ctx.obj["config_file"])
    config_file_path.write_text(yaml.safe_dump({"swh": {"auth": ctx.obj["config"]}}))

    msg = "Token successfully added to configuration file '%s'"
    msg %= click.format_filename(str(config_file_path))
    click.echo(click.style(msg, fg="green"))
