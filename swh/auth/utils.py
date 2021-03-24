# Copyright (C) 2020-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU Affero General Public License version 3, or any later version
# See top-level LICENSE file for more information

from base64 import urlsafe_b64encode
import hashlib
import secrets
from typing import Tuple


def gen_oidc_pkce_codes() -> Tuple[str, str]:
    """
    Generates a code verifier and a code challenge to be used
    with the OpenID Connect authorization code flow with PKCE
    ("Proof Key for Code Exchange", see https://tools.ietf.org/html/rfc7636).

    PKCE replaces the static secret used in the standard authorization
    code flow with a temporary one-time challenge, making it feasible
    to use in public clients.

    The implementation is inspired from that blog post:
    https://www.stefaanlippens.net/oauth-code-flow-pkce.html
    """
    # generate a code verifier which is a long enough random alphanumeric
    # string, only to be used "client side"
    code_verifier_str = secrets.token_urlsafe(60)

    # create the PKCE code challenge by hashing the code verifier with SHA256
    # and encoding the result in URL-safe base64 (without padding)
    code_challenge = hashlib.sha256(code_verifier_str.encode("ascii")).digest()
    code_challenge_str = urlsafe_b64encode(code_challenge).decode("ascii")
    code_challenge_str = code_challenge_str.replace("=", "")

    return code_verifier_str, code_challenge_str
