# Copyright (C) 2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from django.db import models

from swh.auth.django.models import OIDCUser


class AppUser(OIDCUser):
    """AppUser class to demonstrate the use of the OIDCUser which adds some attributes.

    """

    url = models.TextField(null=False)

    class meta:
        app_label = "app-label"
