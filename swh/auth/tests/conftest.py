# Copyright (C) 2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

import pytest


# Alias rf fixture from pytest-django
@pytest.fixture
def request_factory(rf):
    return rf
