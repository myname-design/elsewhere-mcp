"""OAuth resource-server configuration. Never log tokens or JWT claims."""
import asyncio
import os
from urllib.parse import urlsplit

import jwt
from mcp.server.auth.handlers.metadata import ProtectedResourceMetadataHandler
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import ProtectedResourceMetadata
from starlette.responses import Response
from diagnostics import auth_result


def https_url(name):
    value = os.environ.get(name, "")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError(f"{name} must be an HTTPS URL without credentials, query or fragment")
    return value


class JWTVerifier:
    def __init__(self, issuer, resource, jwks_url, subjects, audience=None):
        self.issuer = issuer
        self.resource = resource
        # Scalekit uses res_... as audience; the public MCP URL is still
        # the RFC 9728 resource identifier. Never infer either from a token.
        self.audience = audience if audience is not None else resource
        self.subjects = subjects
        # Fixed administrator-configured JWKS URL; never follow a token's jku/x5u.
        self.keys = jwt.PyJWKClient(jwks_url, timeout=5, lifespan=300)

    async def verify_token(self, token):
        auth_result.set("invalid_token")
        try:
            key = await asyncio.to_thread(self.keys.get_signing_key_from_jwt, token)
            claims = jwt.decode(
                token, key.key, algorithms=["RS256"], audience=self.audience,
                issuer=self.issuer, options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
            if claims["sub"] not in self.subjects:
                auth_result.set("subject_not_allowed")
                return None
            scope = claims.get("scope", "")
            if not isinstance(scope, str):
                auth_result.set("invalid_scope_claim")
                return None
            result = AccessToken(
                token=token, client_id=claims.get("client_id") or claims.get("azp") or claims["sub"],
                subject=claims["sub"], scopes=scope.split(),
                # Map the configured, verified audience to this MCP resource.
                expires_at=int(claims["exp"]), resource=self.resource,
            )
            auth_result.set("verified" if "mcp:tools" in result.scopes else "insufficient_scope")
            return result
        except jwt.ExpiredSignatureError:
            auth_result.set("expired_token")
        except jwt.ImmatureSignatureError:
            auth_result.set("token_not_yet_valid")
        except jwt.InvalidIssuerError:
            auth_result.set("issuer_mismatch")
        except jwt.InvalidAudienceError:
            auth_result.set("audience_mismatch")
        except jwt.MissingRequiredClaimError:
            auth_result.set("missing_required_claim")
        except jwt.InvalidSignatureError:
            auth_result.set("invalid_signature")
        except jwt.InvalidAlgorithmError:
            auth_result.set("invalid_algorithm")
        except jwt.PyJWKClientConnectionError:
            auth_result.set("jwks_unavailable")
        except jwt.PyJWKClientError:
            auth_result.set("signing_key_unavailable")
        except (jwt.PyJWTError, ValueError, TypeError, OSError):
            auth_result.set("invalid_token")
        return None


def remote_security():
    issuer = https_url("OAUTH_ISSUER_URL")
    resource = https_url("MCP_RESOURCE_URL")
    if urlsplit(resource).path != "/mcp":
        raise ValueError("MCP_RESOURCE_URL must end in /mcp")
    jwks = https_url("OAUTH_JWKS_URL")
    audience = os.getenv("OAUTH_AUDIENCE", resource)
    if not audience or audience != audience.strip() or any(c.isspace() for c in audience) or "," in audience:
        raise ValueError("OAUTH_AUDIENCE must be one non-empty audience identifier")
    subjects = {s.strip() for s in os.getenv("OAUTH_ALLOWED_SUBJECTS", "").split(",") if s.strip()}
    if not subjects:
        raise ValueError("OAUTH_ALLOWED_SUBJECTS must identify at least one authorized user")
    origin = urlsplit(resource)
    return {
        "token_verifier": JWTVerifier(issuer, resource, jwks, subjects, audience=audience),
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


def register_discovery_alias(server):
    """Expose the same public metadata at the root URL used by Scalekit guides.

    FastMCP continues to serve the canonical /mcp metadata URL and to advertise
    it in 401 challenges. Authorization endpoints remain on Scalekit.
    """
    auth = server.settings.auth
    if auth is None or auth.resource_server_url is None:
        return
    handler = ProtectedResourceMetadataHandler(ProtectedResourceMetadata(
        resource=auth.resource_server_url,
        authorization_servers=[auth.issuer_url],
        scopes_supported=auth.required_scopes,
    ))

    @server.custom_route("/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])
    async def resource_metadata(request):
        response = Response(status_code=204) if request.method == "OPTIONS" else await handler.handle(request)
        # Public discovery only; does not change MCP endpoint Origin protection.
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        return response
