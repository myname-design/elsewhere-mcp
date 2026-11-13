"""OAuth resource-server configuration. Never log tokens or JWT claims."""
import asyncio
import os
from urllib.parse import urlsplit

import jwt
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings


def https_url(name):
    value = os.environ.get(name, "")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError(f"{name} must be an HTTPS URL without credentials, query or fragment")
    return value


class JWTVerifier:
    def __init__(self, issuer, resource, jwks_url, subjects):
        self.issuer = issuer
        self.resource = resource
        self.subjects = subjects
        # Fixed administrator-configured JWKS URL; never follow a token's jku/x5u.
        self.keys = jwt.PyJWKClient(jwks_url, timeout=5, lifespan=300)

    async def verify_token(self, token):
        try:
            key = await asyncio.to_thread(self.keys.get_signing_key_from_jwt, token)
            claims = jwt.decode(
                token, key.key, algorithms=["RS256"], audience=self.resource,
                issuer=self.issuer, options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
            if claims["sub"] not in self.subjects:
                return None
            scope = claims.get("scope", "")
            if not isinstance(scope, str):
                return None
            return AccessToken(
                token=token, client_id=claims.get("azp") or claims["sub"],
                subject=claims["sub"], scopes=scope.split(),
                expires_at=int(claims["exp"]), resource=self.resource,
            )
        except (jwt.PyJWTError, ValueError, TypeError, OSError):
            return None


def remote_security():
    issuer = https_url("OAUTH_ISSUER_URL")
    resource = https_url("MCP_RESOURCE_URL")
    if urlsplit(resource).path != "/mcp":
        raise ValueError("MCP_RESOURCE_URL must end in /mcp")
    jwks = https_url("OAUTH_JWKS_URL")
    subjects = {s.strip() for s in os.getenv("OAUTH_ALLOWED_SUBJECTS", "").split(",") if s.strip()}
    if not subjects:
        raise ValueError("OAUTH_ALLOWED_SUBJECTS must identify at least one authorized user")
    origin = urlsplit(resource)
    return {
        "token_verifier": JWTVerifier(issuer, resource, jwks, subjects),
        "auth": AuthSettings(
            issuer_url=issuer, resource_server_url=resource,
            required_scopes=["mcp:tools"], validate_token_resource=True,
        ),
        "transport_security": TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[origin.netloc, "127.0.0.1:*", "localhost:*"],
            allowed_origins=[f"https://{origin.netloc}"],
        ),
    }
