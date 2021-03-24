# Copyright (C) 2020-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from typing import Any, Dict, Optional

from django.core.cache import cache
from django.http import HttpRequest
from django.utils import timezone
import sentry_sdk

from swh.auth.django.models import OIDCUser
from swh.auth.django.utils import (
    keycloak_oidc_client,
    oidc_profile_cache_key,
    oidc_user_from_profile,
)
from swh.auth.keycloak import KeycloakOpenIDConnect


def _update_cached_oidc_profile(
    oidc_client: KeycloakOpenIDConnect, oidc_profile: Dict[str, Any], user: OIDCUser
) -> None:
    """
    Update cached OIDC profile associated to a user if needed: when the profile
    is not stored in cache or when the authentication tokens have changed.

    Args:
        oidc_client: KeycloakOpenID wrapper
        oidc_profile: OIDC profile used to authenticate a user
        user: django model representing the authenticated user
    """
    # put OIDC profile in cache or update it after token renewal
    cache_key = oidc_profile_cache_key(oidc_client, user.id)
    if (
        cache.get(cache_key) is None
        or user.access_token != oidc_profile["access_token"]
    ):
        # set cache key TTL as refresh token expiration time
        assert user.refresh_expires_at
        ttl = int(user.refresh_expires_at.timestamp() - timezone.now().timestamp())

        # save oidc_profile in cache
        cache.set(cache_key, user.oidc_profile, timeout=max(0, ttl))


class OIDCAuthorizationCodePKCEBackend:
    """
    Django authentication backend using Keycloak OpenID Connect authorization
    code flow with PKCE ("Proof Key for Code Exchange").

    To use that backend globally in your django application, proceed as follow:

        * add ``"swh.auth.django.backends.OIDCAuthorizationCodePKCEBackend"``
          to the ``AUTHENTICATION_BACKENDS`` django setting

        * configure Keycloak URL, realm and client by adding
          ``SWH_AUTH_SERVER_URL``, ``SWH_AUTH_REALM_NAME`` and ``SWH_AUTH_CLIENT_ID``
          in django settings

        * add ``swh.auth.django.views.urlpatterns`` to your django application URLs

        * add an HTML link targeting the ``"oidc-login"`` django view in your
          application views

        * once a user is logged in, add an HTML link targeting the ``"oidc-logout"``
          django view in your application views (a ``next_path`` query parameter
          can be used to redirect to a view of choice once the user is logged out)

    """

    def authenticate(
        self, request: HttpRequest, code: str, code_verifier: str, redirect_uri: str
    ) -> Optional[OIDCUser]:

        user = None
        try:
            oidc_client = keycloak_oidc_client()
            # try to authenticate user with OIDC PKCE authorization code flow
            oidc_profile = oidc_client.authorization_code(
                code, redirect_uri, code_verifier=code_verifier
            )

            # create Django user
            user = oidc_user_from_profile(oidc_client, oidc_profile)

            # update cached oidc profile if needed
            _update_cached_oidc_profile(oidc_client, oidc_profile, user)

        except Exception as e:
            sentry_sdk.capture_exception(e)

        return user

    def get_user(self, user_id: int) -> Optional[OIDCUser]:
        # get oidc profile from cache
        oidc_client = keycloak_oidc_client()
        oidc_profile = cache.get(oidc_profile_cache_key(oidc_client, user_id))
        if oidc_profile:
            try:
                user = oidc_user_from_profile(oidc_client, oidc_profile)
                # update cached oidc profile if needed
                _update_cached_oidc_profile(oidc_client, oidc_profile, user)
                # restore auth backend
                setattr(user, "backend", f"{__name__}.{self.__class__.__name__}")
                return user
            except Exception as e:
                sentry_sdk.capture_exception(e)
                return None
        else:
            return None
