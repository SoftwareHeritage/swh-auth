# Copyright (C) 2021-2023  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

# WARNING: do not import unnecessary things here to keep cli startup time under
# control

import os
import sys
from typing import Any, Dict, Optional

import click
from click.core import Context

from swh.core.cli import swh as swh_cli_group
from swh.core.config import SWH_GLOBAL_CONFIG

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

DEFAULT_CONFIG_PATH = os.path.join(click.get_app_dir("swh"), SWH_GLOBAL_CONFIG)

DEFAULT_CONFIG: Dict[str, Any] = {
    "keycloak": {
        "server_url": "https://auth.softwareheritage.org/auth/",
        "realm_name": "SoftwareHeritage",
        "client_id": "swh-web",
    }
}


@swh_cli_group.group(name="auth", context_settings=CONTEXT_SETTINGS)
@click.option(
    "-C",
    "--config-file",
    default=DEFAULT_CONFIG_PATH,
    type=click.Path(dir_okay=False, path_type=str),
    help="Path to configuration file",
    envvar="SWH_CONFIG_FILENAME",
    show_default=True,
)
@click.option(
    "--oidc-server-url",
    "-u",
    default=None,
    help=(
        "URL of OpenID Connect server, default to "
        + repr(DEFAULT_CONFIG["keycloak"]["server_url"])
    ),
)
@click.option(
    "--realm-name",
    "-r",
    default=None,
    help=(
        "Name of the OpenID Connect authentication realm, default to "
        + repr(DEFAULT_CONFIG["keycloak"]["realm_name"])
    ),
)
@click.option(
    "--client-id",
    "-c",
    default=None,
    help=(
        "OpenID Connect client identifier in the realm, default to "
        + repr(DEFAULT_CONFIG["keycloak"]["realm_name"])
    ),
)
@click.pass_context
def auth(
    ctx: Context,
    config_file: str,
    oidc_server_url: Optional[str] = None,
    realm_name: Optional[str] = None,
    client_id: Optional[str] = None,
):
    """
    Software Heritage Authentication tools.

    This CLI eases the retrieval of a bearer token to authenticate
    a user querying Software Heritage Web APIs.
    """
    from swh.auth.keycloak import KeycloakOpenIDConnect
    from swh.core import config

    # default config
    cfg = DEFAULT_CONFIG

    # merge config located in config file if any
    cfg = config.merge_configs(cfg, config.read_raw_config(config_file))

    # override config with command parameters if provided
    if "keycloak" not in cfg:
        cfg["keycloak"] = {}
    if oidc_server_url is not None:
        cfg["keycloak"]["server_url"] = oidc_server_url
    if realm_name is not None:
        cfg["keycloak"]["realm_name"] = realm_name
    if client_id is not None:
        cfg["keycloak"]["client_id"] = client_id

    ctx.ensure_object(dict)
    ctx.obj["config_file"] = config_file
    ctx.obj["config"] = cfg

    # Instantiate an OpenId connect client from keycloak auth configuration
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
        if "invoked_by_config" in ctx.parent.__dict__:
            return oidc_info["refresh_token"]
        else:
            click.echo(oidc_info["refresh_token"])
    except KeycloakError as ke:
        ctx.fail(keycloak_error_message(ke))


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
    from swh.auth.utils import get_token_from_config
    from swh.core import config

    cfg = ctx.obj["config"]
    config_file = ctx.obj["config_file"]
    kc_config = cfg["keycloak"]
    oidc_client = ctx.obj["oidc_client"]

    refresh_token = get_token_from_config(
        cfg, kc_config["realm_name"], kc_config["client_id"]
    )

    if refresh_token:
        msg = (
            f"A token was found in {config_file} for realm '{kc_config['realm_name']}' "
            f"and client '{kc_config['client_id']}'"
        )
        click.echo(click.style(msg, fg="green"))
    else:
        refresh_token = token

    if refresh_token:
        next_action = click.prompt(
            text="Would you like to verify the token or generate a new one?",
            type=click.Choice(["verify", "generate"]),
            default="verify",
        )
        if next_action == "generate":
            refresh_token = None

    if not refresh_token:
        if not username:
            click.echo(
                f"A new token will be generated for realm '{kc_config['realm_name']}'"
                f" and client '{kc_config['client_id']}'"
            )
            username = click.prompt(text="Username")
        else:
            click.echo(
                f"A new token for username '{username}' will be generated for realm "
                f"'{kc_config['realm_name']}' and client '{kc_config['client_id']}'"
            )
        setattr(ctx, "invoked_by_config", True)
        refresh_token = ctx.invoke(generate_token, username=username)
        msg = f"Token generation success for username {username}"
        click.echo(click.style(msg, fg="green"))

    # Ensure the token is valid
    try:
        # check if an access token can be generated from the refresh token
        oidc_client.refresh_token(refresh_token=refresh_token)["access_token"]
        if not username:
            # A token has been provided but no username, get one through userinfo
            access_token = oidc_client.refresh_token(refresh_token=refresh_token)[
                "access_token"
            ]
            oidc_info = oidc_client.userinfo(access_token=access_token)
            username = oidc_info["preferred_username"]

        msg = f"Token verification success for username {username}"
        click.echo(click.style(msg, fg="green"))
        # Store the valid token into config object
        cfg = config.merge_configs(
            cfg,
            {
                "keycloak_tokens": {
                    kc_config["realm_name"]: {
                        kc_config["client_id"]: refresh_token,
                    }
                }
            },
        )
    except KeycloakError as ke:
        ctx.fail(keycloak_error_message(ke))

    # Save auth configuration file?
    if not click.confirm(f"Save authentication settings to {config_file}?"):
        ctx.exit(0)

    # Save configuration to file
    config_path = Path(config_file)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.safe_dump(cfg))

    msg = f"Authentication configuration file {config_file} written successfully"
    click.echo(click.style(msg, fg="green"))
