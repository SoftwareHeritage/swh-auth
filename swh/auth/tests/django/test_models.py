# Copyright (C) 2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from typing import Set

import pytest

from swh.auth.django.models import OIDCUser

PERMISSIONS: Set[str] = set(["api", "app-label-read"])
NO_PERMISSION: Set[str] = set()


@pytest.fixture
def oidc_user():
    return OIDCUser(
        id=666,
        username="foo",
        password="bar",
        first_name="foobar",
        last_name="",
        email="foo@bar.org",
    )


@pytest.fixture
def oidc_user_admin(oidc_user):
    oidc_user_admin = oidc_user
    oidc_user_admin.is_active = True
    oidc_user_admin.is_superuser = True
    return oidc_user_admin


def test_django_oidc_user(oidc_user):
    oidc_user.permissions = PERMISSIONS

    assert oidc_user.get_group_permissions() == PERMISSIONS
    assert oidc_user.get_group_permissions(oidc_user) == PERMISSIONS
    assert oidc_user.get_all_permissions() == PERMISSIONS
    assert oidc_user.get_all_permissions(oidc_user) == PERMISSIONS

    assert "api" in PERMISSIONS
    assert oidc_user.has_perm("api") is True
    assert oidc_user.has_perm("something") is False

    assert "app-label-read" in PERMISSIONS
    assert oidc_user.has_module_perms("app-label") is True
    assert oidc_user.has_module_perms("app-something") is False


def test_django_oidc_user_admin(oidc_user_admin):
    oidc_user_admin.permissions = NO_PERMISSION

    assert oidc_user_admin.get_group_permissions() == NO_PERMISSION
    assert oidc_user_admin.get_group_permissions(oidc_user_admin) == NO_PERMISSION

    assert oidc_user_admin.get_all_permissions() == NO_PERMISSION
    assert oidc_user_admin.get_all_permissions(oidc_user) == NO_PERMISSION

    assert "foobar" not in PERMISSIONS
    assert oidc_user_admin.has_perm("foobar") is True
    assert "something" not in PERMISSIONS
    assert oidc_user_admin.has_perm("something") is True

    assert oidc_user_admin.has_module_perms("app-label") is True
    assert oidc_user_admin.has_module_perms("really-whatever-app") is True
