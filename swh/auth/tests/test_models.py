# Copyright (C) 2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from typing import Set

import pytest

from swh.auth.tests.app.apptest.models import AppUser

PERMISSIONS: Set[str] = set(["api", "app-label-read"])
NO_PERMISSION: Set[str] = set()


@pytest.fixture
def appuser():
    return AppUser(
        id=666,
        username="foo",
        password="bar",
        first_name="foobar",
        last_name="",
        email="foo@bar.org",
    )


@pytest.fixture
def appuser_admin(appuser):
    appuser_admin = appuser
    appuser_admin.is_active = True
    appuser_admin.is_superuser = True
    return appuser_admin


def test_django_appuser(appuser):
    appuser.permissions = PERMISSIONS

    assert appuser.get_group_permissions() == PERMISSIONS
    assert appuser.get_group_permissions(appuser) == PERMISSIONS
    assert appuser.get_all_permissions() == PERMISSIONS
    assert appuser.get_all_permissions(appuser) == PERMISSIONS

    assert "api" in PERMISSIONS
    assert appuser.has_perm("api") is True
    assert appuser.has_perm("something") is False

    assert "app-label-read" in PERMISSIONS
    assert appuser.has_module_perms("app-label") is True
    assert appuser.has_module_perms("app-something") is False


def test_django_appuser_admin(appuser_admin):
    appuser_admin.permissions = NO_PERMISSION

    assert appuser_admin.get_group_permissions() == NO_PERMISSION
    assert appuser_admin.get_group_permissions(appuser_admin) == NO_PERMISSION

    assert appuser_admin.get_all_permissions() == NO_PERMISSION
    assert appuser_admin.get_all_permissions(appuser) == NO_PERMISSION

    assert "foobar" not in PERMISSIONS
    assert appuser_admin.has_perm("foobar") is True
    assert "something" not in PERMISSIONS
    assert appuser_admin.has_perm("something") is True

    assert appuser_admin.has_module_perms("app-label") is True
    assert appuser_admin.has_module_perms("really-whatever-app") is True
