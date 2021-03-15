# Copyright (C) 2020-2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from copy import copy
from datetime import datetime, timezone
from typing import Dict, List, Optional
from unittest.mock import Mock

from keycloak.exceptions import KeycloakError
import pytest

from swh.auth.keycloak import KeycloakOpenIDConnect
from swh.auth.tests.sample_data import OIDC_PROFILE, RAW_REALM_PUBLIC_KEY, USER_INFO


class KeycloackOpenIDConnectMock(KeycloakOpenIDConnect):
    """Mock KeycloakOpenIDConnect class to allow testing

    Args:
        server_url: Server main auth url (cf.
            :py:data:`swh.auth.tests.sample_data.SERVER_URL`)
        realm_name: Realm (cf. :py:data:`swh.auth.tests.sample_data.REALM_NAME`)
        client_id: Client id (cf. :py:data:`swh.auth.tests.sample_data.CLIENT_ID`)
        auth_success: boolean flag to simulate authentication success or failure
        exp: expiration delay
        user_groups: user groups configuration (if any)
        user_permissions: user permissions configuration (if any)
        oidc_profile: Dict response from a call to a token authentication query (cf.
            :py:data:`swh.auth.tests.sample_data.OIDC_PROFILE`)
        user_info: Dict response from a call to userinfo query (cf.
            :py:data:`swh.auth.tests.sample_data.USER_INFO`)
        raw_realm_public_key: A raw ascii text representing the realm public key (cf.
            :py:data:`swh.auth.tests.sample_data.RAW_REALM_PUBLIC_KEY`)

    """

    def __init__(
        self,
        server_url: str,
        realm_name: str,
        client_id: str,
        auth_success: bool = True,
        exp: Optional[int] = None,
        user_groups: List[str] = [],
        user_permissions: List[str] = [],
        oidc_profile: Dict = OIDC_PROFILE,
        user_info: Dict = USER_INFO,
        raw_realm_public_key: str = RAW_REALM_PUBLIC_KEY,
    ):
        super().__init__(
            server_url=server_url, realm_name=realm_name, client_id=client_id
        )
        self.exp = exp
        self.user_groups = user_groups
        self.user_permissions = user_permissions
        self._keycloak.public_key = lambda: raw_realm_public_key
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
        self.set_auth_success(auth_success, oidc_profile, user_info)

    def decode_token(self, token):
        options = {}
        if self.auth_success:
            # skip signature expiration and audience checks as we use a static
            # oidc_profile for the tests with expired tokens in it
            options["verify_exp"] = False
            options["verify_aud"] = False
        decoded = super().decode_token(token, options)
        # Merge the user info configured to be part of the decode token
        userinfo = self.userinfo()
        if userinfo is not None:
            decoded = {**decoded, **userinfo}
        # tweak auth and exp time for tests
        auth_time = decoded.get("auth_time", decoded["iat"])
        expire_in = decoded["exp"] - auth_time
        if self.exp is not None:
            decoded["exp"] = self.exp
            auth_time = self.exp - expire_in
            decoded["iat"] = auth_time
            decoded["auth_time"] = auth_time
        else:
            now = int(datetime.now(tz=timezone.utc).timestamp())
            decoded["iat"] = now
            decoded["auth_time"] = now
            decoded["exp"] = now + expire_in
        decoded["groups"] = self.user_groups
        decoded["aud"] = [self.client_id, "account"]
        decoded["azp"] = self.client_id
        if self.user_permissions:
            decoded["resource_access"][self.client_id] = {
                "roles": self.user_permissions
            }
        return decoded

    def set_auth_success(
        self,
        auth_success: bool,
        oidc_profile: Optional[Dict] = None,
        user_info: Optional[Dict] = None,
    ) -> None:
        # following type ignore because mypy is not too happy about affecting mock to
        # method "Cannot assign to a method affecting mock". Ignore for now.
        self.authorization_code = Mock()  # type: ignore
        self.refresh_token = Mock()  # type: ignore
        self.login = Mock()  # type: ignore
        self.userinfo = Mock()  # type: ignore
        self.logout = Mock()  # type: ignore
        self.auth_success = auth_success
        if auth_success:
            self.authorization_code.return_value = copy(oidc_profile)
            self.refresh_token.return_value = copy(oidc_profile)
            self.login.return_value = copy(oidc_profile)
            self.userinfo.return_value = copy(user_info)
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
            self.login.side_effect = exception


def keycloak_mock_factory(
    server_url: str,
    realm_name: str,
    client_id: str,
    auth_success: bool = True,
    exp: Optional[int] = None,
    user_groups: List[str] = [],
    user_permissions: List[str] = [],
    oidc_profile: Dict = OIDC_PROFILE,
    user_info: Dict = USER_INFO,
    raw_realm_public_key: str = RAW_REALM_PUBLIC_KEY,
):
    """Keycloak mock fixture factory. Report to
       :py:class:`swh.auth.pytest_plugin.KeycloackOpenIDConnectMock` docstring.

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
            oidc_profile=oidc_profile,
            user_info=user_info,
            raw_realm_public_key=raw_realm_public_key,
        )

    return keycloak_open_id_connect
