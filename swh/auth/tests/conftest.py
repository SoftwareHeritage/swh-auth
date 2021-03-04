# Copyright (C) 2020-2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from copy import copy
from datetime import datetime, timezone
from typing import Optional
from unittest.mock import Mock

from keycloak.exceptions import KeycloakError
import pytest

from swh.auth.keycloak import KeycloakOpenIDConnect

from .sample_data import (
    OIDC_PROFILE,
    RAW_REALM_PUBLIC_KEY,
    REALM,
    SERVER_URL,
    USER_INFO,
)


class KeycloackOpenIDConnectMock(KeycloakOpenIDConnect):
    """Mock KeycloakOpenIDConnect class to allow testing

    Args:
        auth_success: boolean flag to simulate authentication success or failure
        exp: expiration
        user_groups: user groups configuration (if any)
        user_permissions: user permissions configuration (if any)

    """

    def __init__(
        self,
        server_url: str,
        realm_name: str,
        client_id: str,
        auth_success: bool = True,
        exp: Optional[int] = None,
        user_groups=[],
        user_permissions=[],
    ):
        super().__init__(
            server_url=server_url, realm_name=realm_name, client_id=client_id
        )
        self.exp = exp
        self.user_groups = user_groups
        self.user_permissions = user_permissions
        self._keycloak.public_key = lambda: RAW_REALM_PUBLIC_KEY
        self._keycloak.well_know = lambda: {
            "issuer": f"{self.server_url}realms/{self.realm_name}",
            "authorization_endpoint": (
                f"{self.server_url}realms/"
                f"{self.realm_name}/protocol/"
                "openid-connect/auth"
            ),
            "token_endpoint": (
                f"{self.server_url}realms/{self.realm_name}/"
                "protocol/openid-connect/token"
            ),
            "token_introspection_endpoint": (
                f"{self.server_url}realms/"
                f"{self.realm_name}/protocol/"
                "openid-connect/token/"
                "introspect"
            ),
            "userinfo_endpoint": (
                f"{self.server_url}realms/{self.realm_name}/"
                "protocol/openid-connect/userinfo"
            ),
            "end_session_endpoint": (
                f"{self.server_url}realms/"
                f"{self.realm_name}/protocol/"
                "openid-connect/logout"
            ),
            "jwks_uri": (
                f"{self.server_url}realms/{self.realm_name}/"
                "protocol/openid-connect/certs"
            ),
        }
        self.set_auth_success(auth_success)

    def decode_token(self, token):
        options = {}
        if self.auth_success:
            # skip signature expiration check as we use a static oidc_profile
            # for the tests with expired tokens in it
            options["verify_exp"] = False
        decoded = super().decode_token(token, options)
        # tweak auth and exp time for tests
        expire_in = decoded["exp"] - decoded["auth_time"]
        if self.exp is not None:
            decoded["exp"] = self.exp
            decoded["auth_time"] = self.exp - expire_in
        else:
            decoded["auth_time"] = int(datetime.now(tz=timezone.utc).timestamp())
            decoded["exp"] = decoded["auth_time"] + expire_in
        decoded["groups"] = self.user_groups
        if self.user_permissions:
            decoded["resource_access"][self.client_id] = {
                "roles": self.user_permissions
            }
        return decoded

    def set_auth_success(self, auth_success: bool) -> None:
        # following type ignore because mypy is not too happy about affecting mock to
        # method "Cannot assign to a method affecting mock". Ignore for now.
        self.authorization_code = Mock()  # type: ignore
        self.refresh_token = Mock()  # type: ignore
        self.userinfo = Mock()  # type: ignore
        self.logout = Mock()  # type: ignore
        self.auth_success = auth_success
        if auth_success:
            self.authorization_code.return_value = copy(OIDC_PROFILE)
            self.refresh_token.return_value = copy(OIDC_PROFILE)
            self.userinfo.return_value = copy(USER_INFO)
        else:
            self.authorization_url = Mock()  # type: ignore
            exception = KeycloakError(
                error_message="Authentication failed", response_code=401
            )
            self.authorization_code.side_effect = exception
            self.authorization_url.side_effect = exception
            self.refresh_token.side_effect = exception
            self.userinfo.side_effect = exception
            self.logout.side_effect = exception


def keycloak_mock_factory(
    server_url=SERVER_URL,
    realm_name=REALM,
    client_id="swh-client-id",
    auth_success=True,
    exp=None,
    user_groups=[],
    user_permissions=[],
):
    """Keycloak mock fixture factory

    """

    @pytest.fixture
    def keycloak_open_id_connect():
        return KeycloackOpenIDConnectMock(
            server_url=server_url,
            realm_name=realm_name,
            client_id=client_id,
            auth_success=auth_success,
            exp=exp,
            user_groups=user_groups,
            user_permissions=user_permissions,
        )

    return keycloak_open_id_connect
