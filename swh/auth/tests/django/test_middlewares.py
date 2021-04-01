# Copyright (C) 2020-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information


from django.core.cache import cache
from django.test import modify_settings, override_settings
import pytest

from swh.auth.django.utils import oidc_profile_cache_key, reverse


@pytest.mark.django_db
@override_settings(SWH_AUTH_SESSION_EXPIRED_REDIRECT_VIEW=None)
def test_oidc_session_expired_middleware_missing_setting(client, keycloak_oidc):
    client.login(code="", code_verifier="", redirect_uri="")
    keycloak_oidc.authorization_code.assert_called()

    url = reverse("root")

    with pytest.raises(ValueError, match="setting is mandatory"):
        client.get(url)


@pytest.mark.django_db
@modify_settings(
    MIDDLEWARE={"remove": ["swh.auth.django.middlewares.OIDCSessionExpiredMiddleware"]}
)
def test_oidc_session_expired_middleware_disabled(client, keycloak_oidc):
    # authenticate user

    client.login(code="", code_verifier="", redirect_uri="")
    keycloak_oidc.authorization_code.assert_called()

    url = reverse("root")

    # visit url first to get user from response
    response = client.get(url)
    assert response.status_code == 200

    # simulate OIDC session expiration
    cache.delete(oidc_profile_cache_key(keycloak_oidc, response.wsgi_request.user.id))

    # no redirection when session has expired
    response = client.get(url)
    assert response.status_code == 200


@pytest.mark.django_db
def test_oidc_session_expired_middleware_enabled(client, keycloak_oidc):
    # authenticate user
    client.login(code="", code_verifier="", redirect_uri="")
    keycloak_oidc.authorization_code.assert_called()

    url = reverse("root")

    # visit url first to get user from response
    response = client.get(url)
    assert response.status_code == 200

    # simulate OIDC session expiration
    cache.delete(oidc_profile_cache_key(keycloak_oidc, response.wsgi_request.user.id))

    # should redirect to logout page
    response = client.get(url)
    assert response.status_code == 302
    silent_refresh_url = reverse(
        "logout", query_params={"next_path": url, "remote_user": 1}
    )
    assert response["location"] == silent_refresh_url
