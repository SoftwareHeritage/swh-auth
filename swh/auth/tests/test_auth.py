# Copyright (C) 2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

import pytest

from swh.auth import KeycloakOpenIDConnect

from .conftest import REALM, SERVER_URL, WELL_KNOWN


@pytest.fixture
def keycloak_open_id_connect():
    return KeycloakOpenIDConnect(
        server_url=SERVER_URL, realm_name=REALM, client_id="client-id",
    )


def test_auth_well_known(mock_keycloak, keycloak_open_id_connect):
    well_known_result = keycloak_open_id_connect.well_known()
    assert well_known_result is not None
    assert well_known_result == WELL_KNOWN

    assert mock_keycloak.called
