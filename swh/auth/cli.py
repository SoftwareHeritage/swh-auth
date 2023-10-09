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
    "SWH_AUTH_CONFIG_FILE", os.path.join(click.get_app_dir("swh"), "auth.yml")
)

# Keycloak OpenID Connect defaults
DEFAULT_CONFIG: Dict[str, Any] = {
    "keycloak": {
        "server_url": "https://auth.softwareheritage.org/auth/",
        "realm_name": "SoftwareHeritage",
        "client_id": "swh-web",
    }
}


@swh_cli_group.group(name="auth", context_settings=CONTEXT_SETTINGS)
@click.option(
    "--oidc-server-url",
    "--server-url",
    "server_url",
    default=f"{DEFAULT_CONFIG['keycloak']['server_url']}",
    help=(
        "URL of OpenID Connect server (default to "
        f"\"{DEFAULT_CONFIG['keycloak']['server_url']}\")"
    ),
)
@click.option(
    "--realm-name",
    "realm_name",
    default=f"{DEFAULT_CONFIG['keycloak']['realm_name']}",
    help=(
        "Name of the OpenID Connect authentication realm "
        f"(default to \"{DEFAULT_CONFIG['keycloak']['realm_name']}\")"
    ),
)
@click.option(
    "--client-id",
    "client_id",
    default=f"{DEFAULT_CONFIG['keycloak']['client_id']}",
    help=(
        "OpenID Connect client identifier in the realm "
        f"(default to \"{DEFAULT_CONFIG['keycloak']['client_id']}\")"
    ),
)
@click.option(
    "-C",
    "--config-file",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help=f"Path to authentication configuration file (default: {DEFAULT_CONFIG_PATH})",
)
@click.pass_context
def auth(
    ctx: Context,
    server_url: str,
    realm_name: str,
    client_id: str,
    config_file: str,
):
    """
    Software Heritage Authentication tools.

    This CLI eases the retrieval of a bearer token to authenticate
    a user querying Software Heritage Web APIs.
    """
    from swh.auth.keycloak import KeycloakOpenIDConnect
    from swh.core import config

    # Env var takes precedence on params
    # Params takes precedence on "auth.yml" configuration file
    # Configuration file takes precedence on default auth config values
    # Set auth config to default values
    cfg = DEFAULT_CONFIG

    # Merge with default auth config file
    default_cfg_from_file = config.load_named_config("auth", global_conf=False)
    cfg = config.merge_configs(cfg, default_cfg_from_file)
    # Merge with user config file if any
    if config_file:
        user_cfg_from_file = config.read_raw_config(config_file)
        cfg = config.merge_configs(cfg, user_cfg_from_file)
    else:
        config_file = DEFAULT_CONFIG_PATH
    # Merge with params if any (params load env var too)
    ctx.ensure_object(dict)
    params = {}
    for key in DEFAULT_CONFIG["keycloak"].keys():
        if key in ctx.params:
            params[key] = ctx.params[key]
    if params:
        cfg = config.merge_configs(cfg, {"keycloak": params})

    assert "keycloak" in cfg

    ctx.obj["config_file"] = config_file
    ctx.obj["keycloak"] = cfg["keycloak"]

    # Instantiate an OpenId connect client from keycloak auth configuration
    # The 'keycloak' key is mandatory
    ctx.obj["oidc_client"] = KeycloakOpenIDConnect.from_config(keycloak=cfg["keycloak"])


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
        return oidc_info["refresh_token"]
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


@auth.command("config")
@click.option(
    "--username",
    "username",
    default=None,
    help=("OpenID username"),
)
@click.option(
    "--token",
    "token",
    default=None,
    help=(
        "A valid OpenId connect token to authenticate to "
        f"\"{DEFAULT_CONFIG['keycloak']['server_url']}\""
    ),
)
@click.pass_context
def auth_config(ctx: Context, username: str, token: str):
    """Guided authentication configuration for Software Heritage web services

    If you do not already have an account, create one at
    "https://archive.softwareheritage.org/"
    """
    from pathlib import Path

    import yaml

    from swh.auth.keycloak import KeycloakError, keycloak_error_message

    assert "oidc_client" in ctx.obj
    oidc_client = ctx.obj["oidc_client"]

    # params > config
    # Ensure we get a token
    raw_token: str = ""

    if token:
        # Verify the token is valid
        raw_token = token
    elif "token" in ctx.obj["keycloak"] and ctx.obj["keycloak"]["token"]:
        # A token entry exists in keycloak auth config object
        msg = f"A token entry exists in {ctx.obj['config_file']}\n"
        click.echo(click.style(msg, fg="green"))
        next_action = click.prompt(
            text="Would you like to verify it or generate a new one?",
            type=click.Choice(["verify", "generate"]),
            default="verify",
        )
        if next_action == "verify":
            raw_token = ctx.obj["keycloak"]["token"]

    if not raw_token:
        if not username:
            username = click.prompt(text="Username")
        raw_token = ctx.invoke(generate_token, username=username)

    assert raw_token
    refresh_token = raw_token.strip()

    # Ensure the token is valid by getting user info
    try:
        # userinfo endpoint needs an access_token
        access_token = oidc_client.refresh_token(refresh_token=refresh_token)[
            "access_token"
        ]
        oidc_info = oidc_client.userinfo(access_token=access_token)
        msg = (
            f"Token verification success for username {oidc_info['preferred_username']}"
        )
        click.echo(click.style(msg, fg="green"))
        # Store the valid token into keycloak auth config object
        ctx.obj["keycloak"]["token"] = refresh_token
    except KeycloakError as ke:
        msg = keycloak_error_message(ke)
        click.echo(click.style(msg, fg="red"))
        ctx.exit(1)

    # Save auth configuration file?
    if not click.confirm(
        "Save authentication settings to\n" f"{ctx.obj['config_file']}?"
    ):
        sys.exit(1)

    # Save configuration to file
    config_path = Path(ctx.obj["config_file"])
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.safe_dump({"keycloak": ctx.obj["keycloak"]}))

    msg = "\nAuthentication configuration file '%s' written successfully"
    msg %= click.format_filename(str(config_path))
    click.echo(click.style(msg, fg="green"))
