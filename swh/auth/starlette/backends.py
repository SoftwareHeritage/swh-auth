# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from datetime import datetime
import hashlib
from typing import Any, Dict, Optional, Tuple

from aiocache.base import BaseCache
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
)
from starlette.requests import HTTPConnection

from swh.auth.keycloak import (
    ExpiredSignatureError,
    KeycloakError,
    KeycloakOpenIDConnect,
    keycloak_error_message,
)


class BearerTokenAuthBackend(AuthenticationBackend):
    """
    Starlette authentication backend using Keycloak OpenID Connect authorization

    An Keycloak server, realm and a cache to store access tokens must be provided
    """

    def __init__(
        self, server_url: str, realm_name: str, client_id: str, cache: BaseCache
    ):
        """
        Args:
            server_url: Keycloak URL
            realm_name: Keycloak realm name
            client_id: Keycloak client ID
            cache: An aiocache cache instance
        """
        self.client_id = client_id
        self.oidc_client = KeycloakOpenIDConnect(
            server_url=server_url,
            realm_name=realm_name,
            client_id=client_id,
        )
        self.cache = cache

    def _get_token_from_header(self, auth_header: str) -> str:
        try:
            auth_type, bearer_token = auth_header.split(" ", 1)
        except ValueError:
            raise AuthenticationError("Invalid auth header")
        if auth_type != "Bearer":
            raise AuthenticationError("Invalid or unsupported authorization type")
        return bearer_token

    def _get_token_cache_key(self, refresh_token) -> str:
        hasher = hashlib.sha1()
        hasher.update(refresh_token.encode("ascii"))
        return f"api_token_{hasher.hexdigest()}"

    def _get_new_access_token(self, refresh_token: str) -> Dict[str, Any]:
        try:
            access_token = self.oidc_client.refresh_token(refresh_token)
        except KeycloakError as e:
            raise AuthenticationError(
                "Invalid or expired user token", keycloak_error_message(e)
            )
        return access_token

    def _decode_token(self, access_token: str) -> Optional[Dict[str, Any]]:
        if not access_token:
            return None
        try:
            decoded_token = self.oidc_client.decode_token(access_token)
        except (KeycloakError, UnicodeEncodeError, ExpiredSignatureError):
            # token is eitehr too old or an invalid one
            decoded_token = None
        return decoded_token

    async def authenticate(
        self, conn: HTTPConnection
    ) -> Optional[Tuple[AuthCredentials, SimpleUser]]:
        auth_header = conn.headers.get("Authorization")
        if auth_header is None:
            # anonymous user
            return None
        refresh_token = self._get_token_from_header(auth_header)
        # get the cache key
        cache_key = self._get_token_cache_key(refresh_token)
        # read access token from the cache
        access_token = await self.cache.get(cache_key)
        decoded_token = self._decode_token(access_token)
        if not access_token or not decoded_token:
            access_token = self._get_new_access_token(refresh_token)["access_token"]
            decoded_token = self._decode_token(access_token)
            if not decoded_token:
                raise AuthenticationError("Access token failed to be decoded")
            exp = datetime.fromtimestamp(decoded_token["exp"])
            ttl = int(exp.timestamp() - datetime.now().timestamp())
            await self.cache.set(cache_key, access_token, ttl=ttl)
        # set user scopes
        realm_access = decoded_token.get("realm_access", {})
        user_scopes = realm_access.get("roles", [])
        resource_access = decoded_token.get("resource_access", {})
        client_resource_access = resource_access.get(self.client_id, {})
        user_scopes += client_resource_access.get("roles", [])
        return AuthCredentials(scopes=user_scopes), SimpleUser(
            decoded_token["preferred_username"]
        )
