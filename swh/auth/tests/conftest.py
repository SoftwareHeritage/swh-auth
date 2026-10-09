# Copyright (C) 2021-2026  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from pathlib import Path
import re

import pytest
from rest_framework.test import APIClient, APIRequestFactory


# Alias rf fixture from pytest-django
@pytest.fixture
def request_factory(rf):
    return rf


# Fixture to get test client from Django REST Framework
@pytest.fixture(scope="module")
def api_client():
    return APIClient()


# Fixture to get API request factory from Django REST Framework
@pytest.fixture(scope="module")
def api_request_factory():
    return APIRequestFactory()


@pytest.fixture
def kc_login_page(datadir):
    return (Path(datadir) / "kc_login.html").read_text()


@pytest.fixture
def login_action_url(kc_login_page):
    match = re.search(r'^.*"loginAction": "(.+)".*$', kc_login_page, re.MULTILINE)
    return match.group(1)
