# Copyright (C) 2020-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY
from django.http.response import HttpResponseRedirect

from swh.auth.django.utils import reverse


class OIDCSessionExpiredMiddleware:
    """
    Middleware for checking OpenID Connect user session expiration.

    That middleware detects when a user previously logged in using
    the OpenID Connect authentication backend got his session expired.

    In that case it will perform a redirection to a django view whose
    name must be set in the ``SWH_AUTH_SESSION_EXPIRED_REDIRECT_VIEW``
    django setting (typically a logout view).

    The following query parameter will be set for that view:

      * ``next_path``: requested URL before the detection of the session expiration
      * ``remote_user``: indicates that the user was previously authenticated with OIDC

    """

    def __init__(self, get_response=None):
        self.get_response = get_response
        self.redirect_view = getattr(
            settings, "SWH_AUTH_SESSION_EXPIRED_REDIRECT_VIEW", None
        )
        if self.redirect_view is None:
            raise ValueError(
                "SWH_AUTH_SESSION_EXPIRED_REDIRECT_VIEW django setting "
                "is mandatory to instantiate OIDCSessionExpiredMiddleware class"
            )
        self.exempted_urls = [
            reverse(v)
            for v in (
                self.redirect_view,
                "oidc-login",
                "oidc-login-complete",
                "oidc-logout",
            )
        ]

    def __call__(self, request):
        if (
            request.method != "GET"
            or request.user.is_authenticated
            or BACKEND_SESSION_KEY not in request.session
            or "OIDC" not in request.session[BACKEND_SESSION_KEY]
            or request.path in self.exempted_urls
        ):
            return self.get_response(request)

        # At that point, we know that a OIDC user was previously logged in
        # and his session has expired.
        # Redirect to a view specified in django settings.
        next_path = request.get_full_path()
        logout_url = reverse(
            self.redirect_view, query_params={"next_path": next_path, "remote_user": 1}
        )
        return HttpResponseRedirect(logout_url)
