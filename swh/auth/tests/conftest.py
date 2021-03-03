# Copyright (C) 2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

import pytest

from swh.auth import KeycloakOpenIDConnect

from .sample_data import OIDC_PROFILE, REALM, SERVER_URL, WELL_KNOWN


@pytest.fixture
def keycloak_open_id_connect():
    return KeycloakOpenIDConnect(
        server_url=SERVER_URL, realm_name=REALM, client_id="client-id",
    )


@pytest.fixture
def mock_keycloak(requests_mock):
    """Keycloak with most endpoints available.

    """
    requests_mock.get(WELL_KNOWN["well-known"], json=WELL_KNOWN)
    requests_mock.post(WELL_KNOWN["token_endpoint"], json=OIDC_PROFILE)

    return requests_mock


@pytest.fixture
def mock_keycloak_refused_auth(requests_mock):
    """Keycloak with token endpoint refusing authentication.

    """
    requests_mock.post(WELL_KNOWN["token_endpoint"], status_code=401)
    return requests_mock
