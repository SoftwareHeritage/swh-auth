# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from aiocache import Cache
import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from swh.auth.starlette import backends
from swh.auth.tests.sample_data import USER_INFO


@pytest.fixture
def app_with_auth_backend(keycloak_oidc):
    backend = backends.BearerTokenAuthBackend(
        server_url="https://example.com",
        realm_name="example",
        client_id="example",
        cache=Cache(),  # Dummy cache
    )
    backend.oidc_client = keycloak_oidc
    middleware = [
        Middleware(
            AuthenticationMiddleware,
            backend=backend,
        )
    ]

    def homepage(request):
        if request.user.is_authenticated:
            return PlainTextResponse("Hello " + request.user.username)
        return PlainTextResponse("Hello")

    app = Starlette(routes=[Route("/", homepage)], middleware=middleware)
    return app


@pytest.fixture
def client(app_with_auth_backend):
    return TestClient(app_with_auth_backend)


def test_anonymous_access(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Hello"


def test_invalid_auth_header(client):
    client.headers = {"Authorization": "invalid"}
    response = client.get("/")
    assert response.status_code == 400
    assert response.text == "Invalid auth header"


def test_invalid_auth_type(client):
    client.headers = {"Authorization": "Basic invalid"}
    response = client.get("/")
    assert response.status_code == 400
    assert response.text == "Invalid or unsupported authorization type"


def test_invalid_refresh_token(client, keycloak_oidc):
    keycloak_oidc.set_auth_success(False)
    client.headers = {"Authorization": "Bearer invalid-valid-token"}
    response = client.get("/")
    assert response.status_code == 400
    assert "Invalid or expired user token" in response.text


def test_success_token(client, keycloak_oidc):
    client.headers = {"Authorization": "Bearer valid-token"}
    response = client.get("/")

    assert response.status_code == 200
    assert response.text == f'Hello {USER_INFO["preferred_username"]}'
