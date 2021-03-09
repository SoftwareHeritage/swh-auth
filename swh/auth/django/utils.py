# Copyright (C) 2020-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from swh.auth.django.models import OIDCUser
from swh.auth.keycloak import KeycloakOpenIDConnect


def oidc_user_from_decoded_token(
    decoded_token: Dict[str, Any], client_id: Optional[str] = None
) -> OIDCUser:
    """Create an OIDCUser out of a decoded token

    Args:
        decoded_token: Decoded token Dict
        client_id: Optional client id of the keycloak client instance used to decode
            the token. If not provided, the permissions will be empty.

    Returns:
        The OIDCUser instance

    """
    # compute an integer user identifier for Django User model
    # by concatenating all groups of the UUID4 user identifier
    # generated by Keycloak and converting it from hex to decimal
    user_id = int("".join(decoded_token["sub"].split("-")), 16)

    # create a Django user that will not be saved to database
    user = OIDCUser(
        id=user_id,
        username=decoded_token["preferred_username"],
        password="",
        first_name=decoded_token["given_name"],
        last_name=decoded_token["family_name"],
        email=decoded_token["email"],
    )

    # set is_staff user property based on groups
    if "groups" in decoded_token:
        user.is_staff = "/staff" in decoded_token["groups"]

    if client_id:
        # extract user permissions if any
        resource_access = decoded_token.get("resource_access", {})
        client_resource_access = resource_access.get(client_id, {})
        permissions = client_resource_access.get("roles", [])
    else:
        permissions = []

    user.permissions = set(permissions)

    # add user sub to custom User proxy model
    user.sub = decoded_token["sub"]

    return user


def oidc_user_from_profile(
    oidc_client: KeycloakOpenIDConnect, oidc_profile: Dict[str, Any]
) -> OIDCUser:
    """Initialize an OIDCUser out of an oidc profile dict.

    Args:
        oidc_client: KeycloakOpenIDConnect used to discuss with keycloak
        oidc_profile: OIDC profile retrieved once connected to keycloak

    Returns:
        OIDCUser instance parsed out of the token received.

    """

    # decode JWT token
    decoded_token = oidc_client.decode_token(oidc_profile["access_token"])

    # create OIDCUser from decoded token
    user = oidc_user_from_decoded_token(decoded_token, client_id=oidc_client.client_id)

    # get authentication init datetime
    auth_datetime = datetime.fromtimestamp(decoded_token["auth_time"])
    exp_datetime = datetime.fromtimestamp(decoded_token["exp"])

    # compute OIDC tokens expiration date
    oidc_profile["expires_at"] = exp_datetime
    oidc_profile["refresh_expires_at"] = auth_datetime + timedelta(
        seconds=oidc_profile["refresh_expires_in"]
    )

    # add OIDC profile data to custom User proxy model
    for key, val in oidc_profile.items():
        if hasattr(user, key):
            setattr(user, key, val)

    return user
