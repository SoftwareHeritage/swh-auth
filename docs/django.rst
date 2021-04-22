Django components
=================

``swh-auth`` implements some generic backends, models, views and middlewares
to easily authenticate a user with Keycloak and OpenID Connect.


OIDC User model
---------------

When ``swh-auth`` authenticates users with OIDC in a Django application,
it creates an instance of the :class:`swh.auth.django.models.OIDCUser`
model and attaches it to the input ``django.http.HttpRequest`` object.

That model acts as a proxy for the ``django.contrib.auth.models.User`` model
and is not persisted to database as user information is already stored
in Keycloak database. As a consequence it will not be considered when calling
the ``makemigrations`` command from Django application management CLI.


Authentication backends
-----------------------

``swh-auth`` provides two authentication backends to login users in
Django applications:

- :class:`swh.auth.django.backends.OIDCAuthorizationCodePKCEBackend`: authenticate
  users from a Web application UI

- :class:`swh.auth.django.backends.OIDCBearerTokenAuthentication`: authenticate
  REST API users from bearer tokens sent in HTTP Authorization headers.

These backends need to be configured through the following Django settings:

- ``SWH_AUTH_SERVER_URL``: Base URL of the Keycloak server to interact with

- ``SWH_AUTH_REALM_NAME``: Name of the realm to use in the Keycloak instance

- ``SWH_AUTH_CLIENT_ID``: Name of the client to use in the realm

.. warning::

  These backends internally use the Django cache to store authenticated user data.
  In production environment, it is important to ensure the cache will be shared
  across the multiple WSGI workers (by using Django memcached cache backend
  for instance).

Authorization Code flow with PKCE backend
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This backend can be used to authenticate users with the OpenID Connect Authorization
Code flow with PKCE (`Proof Key for Code Exchange`_).

PKCE replaces the static secret used in the standard authorization code flow with a
temporary one-time challenge, making it feasible to use in public clients.

When using that backend, users are redirected to the Keycloak login UI and are
asked to enter their credentials. Once successfully authenticated, users will
be redirected back to the Django application.

To use that backend, add ``"swh.auth.django.backends.OIDCAuthorizationCodePKCEBackend"``
to the ``AUTHENTICATION_BACKENDS`` Django setting.

The backend must be used in collaboration with the dedicated :ref:`login-logout-views`
implementing the authentication flow.

Bearer token backend
^^^^^^^^^^^^^^^^^^^^

This backend for Django REST Framework enables to authenticate Web API users by sending
long-lived OpenID Connect refresh tokens in HTTP Authorization headers.

Long lived refresh tokens can be generated in Keycloak by opening an OpenID Connect
session with the following scope: ``openid offline_access``.

To use that backend, add ``"swh.auth.django.backends.OIDCBearerTokenAuthentication"``
to the ``REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]`` Django setting.

Users can then perform authenticated Web API calls by sending their refresh token
in HTTP Authorization headers, for instance when using ``curl``::

  curl -H "Authorization: Bearer ${TOKEN}" https://....

.. _login-logout-views:

Login / logout views
--------------------

In order to login / logout a user with OIDC Authorization code flow with PKCE, two
dedicated Django views are available in ``swh-auth``:

- ``oidc-login`` (``/oidc/login/`` URL path): initiate authentication flow

- ``oidc-logout`` (``/oidc/logout/`` URL path): terminate OIDC user session, a ``next_path``
  query parameter can be used to redirect to a view of choice once a user is logged out

Add ``swh.auth.django.views.urlpatterns`` to your Django application URLs to use them.

Middlewares
-----------

``swh-auth`` provides the :class:`swh.auth.django.middlewares.OIDCSessionExpiredMiddleware`
middleware.

That middleware detects when a user previously logged in using the OpenID Connect
authentication backend got his session expired.

In that case it redirects to a Django view whose name is set in the
``SWH_AUTH_SESSION_EXPIRED_REDIRECT_VIEW`` Django setting (typically a logout view).

The following query parameter will be set for that view:

- ``next_path``: requested URL before the detection of the OIDC session expiration

- ``remote_user``: indicates that the user was previously authenticated with OIDC

Minimal application example
---------------------------

A sample minimal Django application using all the features mentioned above can be
found in `swh-auth Django tests tree`_.

.. _Proof Key for Code Exchange: https://tools.ietf.org/html/rfc7636

.. _swh-auth Django tests tree: https://forge.softwareheritage.org/source/swh-auth/browse/master/swh/auth/tests/django/app/apptest/
