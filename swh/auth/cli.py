# Copyright (C) 2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

# WARNING: do not import unnecessary things here to keep cli startup time under
# control

import sys

import click
from click.core import Context

from swh.core.cli import swh as swh_cli_group

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@swh_cli_group.group(name="auth", context_settings=CONTEXT_SETTINGS)
@click.option(
    "--oidc-server-url",
    "oidc_server_url",
    default="https://auth.softwareheritage.org/auth/",
    help=(
        "URL of OpenID Connect server (default to "
        '"https://auth.softwareheritage.org/auth/")'
    ),
)
@click.option(
    "--realm-name",
    "realm_name",
    default="SoftwareHeritage",
    help=(
        "Name of the OpenID Connect authentication realm "
        '(default to "SoftwareHeritage")'
    ),
)
@click.option(
    "--client-id",
    "client_id",
    default="swh-web",
    help=("OpenID Connect client identifier in the realm " '(default to "swh-web")'),
)
@click.pass_context
def auth(ctx: Context, oidc_server_url: str, realm_name: str, client_id: str):
    """
    Software Heritage Authentication tools.

    This CLI eases the retrieval of a bearer token to authenticate
    a user querying Software Heritage Web APIs.
    """
    from swh.auth.keycloak import KeycloakOpenIDConnect

    ctx.ensure_object(dict)
    ctx.obj["oidc_client"] = KeycloakOpenIDConnect(
        oidc_server_url, realm_name, client_id
    )


@auth.command("generate-token")
@click.argument("username")
@click.pass_context
def generate_token(ctx: Context, username: str):
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
