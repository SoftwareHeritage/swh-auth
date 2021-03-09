# Copyright (C) 2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from copy import copy
from datetime import datetime

from swh.auth.django.utils import oidc_user_from_decoded_token, oidc_user_from_profile
from swh.auth.tests.sample_data import CLIENT_ID, DECODED_TOKEN, OIDC_PROFILE


def test_oidc_user_from_decoded_token():
    user = oidc_user_from_decoded_token(DECODED_TOKEN)

    assert user.id == 338521271020811424925120118444075479552
    assert user.username == "johndoe"
    assert user.password == ""
    assert user.first_name == "John"
    assert user.last_name == "Doe"
    assert user.email == "john.doe@example.com"
    assert user.is_staff is False
    assert user.permissions == set()
    assert user.sub == "feacd344-b468-4a65-a236-14f61e6b7200"


def test_oidc_user_from_decoded_token2():
    decoded_token = copy(DECODED_TOKEN)
    decoded_token["groups"] = ["/staff", "api"]
    decoded_token["resource_access"] = {CLIENT_ID: {"roles": ["read-api"]}}

    user = oidc_user_from_decoded_token(decoded_token, client_id=CLIENT_ID)

    assert user.id == 338521271020811424925120118444075479552
    assert user.username == "johndoe"
    assert user.password == ""
    assert user.first_name == "John"
    assert user.last_name == "Doe"
    assert user.email == "john.doe@example.com"
    assert user.is_staff is True
    assert user.permissions == {"read-api"}
    assert user.sub == "feacd344-b468-4a65-a236-14f61e6b7200"


def test_oidc_user_from_profile(keycloak_mock):
    date_now = datetime.now()

    user = oidc_user_from_profile(keycloak_mock, OIDC_PROFILE)

    assert user.id == 338521271020811424925120118444075479552
    assert user.username == "johndoe"
    assert user.password == ""
    assert user.first_name == "John"
    assert user.last_name == "Doe"
    assert user.email == "john.doe@example.com"
    assert user.is_staff is False
    assert user.permissions == set()
    assert user.sub == "feacd344-b468-4a65-a236-14f61e6b7200"

    assert isinstance(user.expires_at, datetime)
    assert date_now <= user.expires_at
    assert isinstance(user.refresh_expires_at, datetime)
    assert date_now <= user.refresh_expires_at
