# Copyright (C) 2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information


from swh.auth.pytest_plugin import keycloak_mock_factory
from swh.auth.tests.sample_data import CLIENT_ID, REALM_NAME, SERVER_URL

# keycloak fixture used within tests (cf. test_keycloak.py, test_utils.py)
keycloak_mock = keycloak_mock_factory(
    server_url=SERVER_URL, realm_name=REALM_NAME, client_id=CLIENT_ID,
)
