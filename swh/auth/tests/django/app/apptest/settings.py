# Copyright (C) 2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from swh.auth.tests.sample_data import CLIENT_ID, REALM_NAME, SERVER_URL

SECRET_KEY = "o+&ayiuk(y^wh4ijz5e=c2$$kjj7g^6r%z+8d*c0lbpfs##k#7"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "swh.auth.tests.django.app.apptest",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "swh.auth.django.middlewares.OIDCSessionExpiredMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "swh.auth.tests.django.app.apptest.urls"

DATABASES = {
    "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": "swh-auth-test-db",}
}

SESSION_ENGINE = "django.contrib.sessions.backends.cache"

AUTHENTICATION_BACKENDS = [
    "swh.auth.django.backends.OIDCAuthorizationCodePKCEBackend",
]

SWH_AUTH_SERVER_URL = SERVER_URL
SWH_AUTH_REALM_NAME = REALM_NAME
SWH_AUTH_CLIENT_ID = CLIENT_ID
SWH_AUTH_SESSION_EXPIRED_REDIRECT_VIEW = "logout"

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer",),
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "swh.auth.django.backends.OIDCBearerTokenAuthentication",
    ],
}
