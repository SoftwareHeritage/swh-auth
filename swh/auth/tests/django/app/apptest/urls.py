# Copyright (C) 2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from django.conf.urls import url
from django.http import HttpResponse

from swh.auth.django.views import urlpatterns as auth_urlpatterns


def _root_view(request):
    return HttpResponse("Hello World !")


urlpatterns = [url(r"^$", _root_view, name="root")] + auth_urlpatterns
