Software Heritage - Authentication
==================================

``swh-auth`` is a set of utility libraries related to user authentication
in applications and services based on the use of `Keycloak`_ and `OpenID Connect`_.

`Keycloak`_ is an open source software enabling single sign-on (SSO) with identity
and access management.

`OpenID Connect`_ (OIDC) is an authentication layer on top of `OAuth 2.0`_, widely
used in modern web applications and services.

``swh-auth`` notably offers the following features:

- the ``swh.auth.keycloak.KeycloakOpenIDConnect`` class to ease the
  interaction with a Keycloak server

- a ``pytest`` plugin with the ``keycloak_oidc`` fixture to mock Keycloak
  responses in unit tests

- generic backends, views and middlewares to easily plug OpenID Connect authentication
  in any `Django`_ or `Django REST framework`_ application


.. _Keycloak: https://www.keycloak.org/

.. _OpenID Connect: https://openid.net/connect/

.. _OAuth 2.0: https://oauth.net/2/

.. _Django: https://www.djangoproject.com/

.. _Django REST framework: https://www.django-rest-framework.org/