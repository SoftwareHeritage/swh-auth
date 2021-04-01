# Copyright (C) 2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from django.conf.urls import url
from django.contrib.auth.views import LogoutView
from django.http import HttpResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response

from swh.auth.django.views import urlpatterns as auth_urlpatterns


def _root_view(request):
    return HttpResponse("Hello World !")


@api_view()
def _api_view_test(request):
    return Response({"message": "Hello World !"})


urlpatterns = [
    url(r"^$", _root_view, name="root"),
    url(r"^api/test$", _api_view_test, name="api-test"),
    url(r"^logout/$", LogoutView.as_view(), name="logout"),
] + auth_urlpatterns
