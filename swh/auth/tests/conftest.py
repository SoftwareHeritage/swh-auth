# Copyright (C) 2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

import pytest

SERVER_URL = "http://keycloak:8080/keycloak/auth/"
REALM = "SoftwareHeritage"

WELL_KNOWN = {
    "issuer": f"{SERVER_URL}realms/SoftwareHeritage",
    "well-known": f"{SERVER_URL}realms/{REALM}/.well-known/openid-configuration",
    "authorization_endpoint": f"{SERVER_URL}realms/{REALM}/protocol/openid-connect/auth",  # noqa
    "token_endpoint": f"{SERVER_URL}realms/{REALM}/protocol/openid-connect/token",
    "introspection_endpoint": f"{SERVER_URL}realms/{REALM}/protocol/openid-connect/token/introspect",  # noqa
    "userinfo_endpoint": f"{SERVER_URL}realms/{REALM}/protocol/openid-connect/userinfo",
    "end_session_endpoint": f"{SERVER_URL}realms/{REALM}/protocol/openid-connect/logout",  # noqa
    "jwks_uri": "{SERVER_URL}realms/{REALM}/protocol/openid-connect/certs",
    "check_session_iframe": "{SERVER_URL}realms/{REALM}/protocol/openid-connect/login-status-iframe.html",  # noqa
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "refresh_token",
        "password",
        "client_credentials",
    ],
    "response_types_supported": [
        "code",
        "none",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token",
    ],
    "subject_types_supported": ["public", "pairwise"],
    "id_token_signing_alg_values_supported": [
        "PS384",
        "ES384",
        "RS384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
    ],
    "id_token_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"],
    "id_token_encryption_enc_values_supported": [
        "A256GCM",
        "A192GCM",
        "A128GCM",
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
    ],
    "userinfo_signing_alg_values_supported": [
        "PS384",
        "ES384",
        "RS384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
        "none",
    ],
    "request_object_signing_alg_values_supported": [
        "PS384",
        "ES384",
        "RS384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
        "none",
    ],
    "response_modes_supported": ["query", "fragment", "form_post"],
    "registration_endpoint": "{SERVER_URL}realms/{REALM}/clients-registrations/openid-connect",  # noqa
    "token_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt",
    ],
    "token_endpoint_auth_signing_alg_values_supported": [
        "PS384",
        "ES384",
        "RS384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
    ],
    "claims_supported": [
        "aud",
        "sub",
        "iss",
        "auth_time",
        "name",
        "given_name",
        "family_name",
        "preferred_username",
        "email",
        "acr",
    ],
    "claim_types_supported": ["normal"],
    "claims_parameter_supported": True,
    "scopes_supported": [
        "openid",
        "microprofile-jwt",
        "web-origins",
        "roles",
        "phone",
        "address",
        "email",
        "profile",
        "offline_access",
    ],
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
    "require_request_uri_registration": True,
    "code_challenge_methods_supported": ["plain", "S256"],
    "tls_client_certificate_bound_access_tokens": True,
    "revocation_endpoint": "{SERVER_URL}realms/{REALM}/protocol/openid-connect/revoke",
    "revocation_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt",
    ],
    "revocation_endpoint_auth_signing_alg_values_supported": [
        "PS384",
        "ES384",
        "RS384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
    ],
    "backchannel_logout_supported": True,
    "backchannel_logout_session_supported": True,
}


@pytest.fixture
def mock_keycloak(requests_mock):
    requests_mock.get(WELL_KNOWN["well-known"], json=WELL_KNOWN)

    return requests_mock
