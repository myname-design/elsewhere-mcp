# Elsewhere MCP integration audit — 2026-11-14

## Scope and result

Reviewed upstream main `c36c944d89be458341f990a22049a38419f89b45` (all repository
files checked against GitHub blob hashes). Previous work was preserved separately.
This change is a compatibility/observability improvement, **not a claim that
ChatGPT's installation or Scalekit's reauthorization failure is fixed**.

No production deployment, environment-variable change, merge, whitelist expansion,
Origin expansion, or authentication bypass was performed. GitHub was accessible;
Render/Scalekit administrative APIs and an interactive signed-in ChatGPT browser
were not available. Public HTTP checks are not a substitute for those permissions.

The success criterion (ChatGPT discovers and actually calls all 12 tools on
Render) remains **unverified**. No real user access/refresh/ID token was obtained.

## Live evidence

Endpoint: `https://elsewhere-mcp-yg9a.onrender.com/mcp`.
Issuer: `https://gdvgwlz6ltn2q.scalekit.dev/resources/res_151986736321265672`.

| Probe | Observed result | What it establishes |
| --- | --- | --- |
| GET `/healthz` | 200, `status=ok` | Process responds; does not prove deployed commit or tool dependencies |
| GET `/.well-known/oauth-protected-resource/mcp` | 200 | Correct resource URL, resource-specific issuer, `mcp:tools`, header bearer |
| GET `/.well-known/oauth-protected-resource` | 200, same metadata | Both discovery routes exist |
| Anonymous POST `/mcp` initialize | 401, `WWW-Authenticate` points to canonical discovery | Expected authentication challenge, not evidence of rejection after login |
| Resource-specific AS metadata | 200 | S256; DCR; CIMD; authorization_code/refresh_token; exact issuer; callback `iss` support |
| Scalekit `/keys` | 200, RSA/RS256 signing key | Public JWKS reachable from the audit machine, not proof of Render egress |
| ChatGPT public CIMD document | 200 | Advertises `none` and `private_key_jwt`; Scalekit advertises `none`, so there is an intersection |
| DCR diagnostic client registration | 200 with client identifier | Registration endpoint works; not a user authorization |
| New DCR authorization request with S256 | Redirects to hosted login, then 200 | Initial authorization can reach login |
| New ChatGPT CIMD authorization request with S256 | Redirects to hosted login, then 200 | Public CIMD accepted far enough to start login |
| Same flows with deliberately invalid synthetic `id_token_hint` | Callback `login_required`, description identifies invalid hint | Reproduces the reported error at Scalekit's authorize endpoint, before MCP |
| Error callback in those probes | Original `state`, exact resource issuer `iss` | Those synthetic callbacks include both fields; says nothing about the user's actual callback |
| Exchange deliberately invalid authorization code | 400 `invalid_grant` | Token endpoint reached and rejected invalid grant; not a successful exchange or PKCE-verifier test |

The resource-prefixed authorize endpoint first returns a 307 to the environment's
`/oauth/authorize`; following that redirect is necessary to observe the login or
error result. Synthetic callback redirects were inspected but **not followed into
ChatGPT**. No diagnostic login/consent was completed.

One separate client named **Elsewhere diagnostic PKCE client 2026-11-14** was
created for the explicitly requested DCR test, using a loopback callback. Scalekit
issued registration credentials even though `none` was requested; they were not
printed, committed or used to grant data access. Existing clients/users were not
deleted or modified. This client is not intended for the production ChatGPT link.

Resource-specific OIDC discovery returned 404 at both tested forms. The RFC 8414
OAuth authorization-server discovery succeeds; OIDC discovery is not required to
repair the working MCP resource discovery. Do not replace the resource issuer
with the environment-level OIDC issuer as a speculative fix.

## Confirmed defects and unresolved causes

1. **Missing diagnostic distinction, confirmed:** main's `JWTVerifier.verify_token`
   returns `None` for signature, issuer, audience, whitelist and JWKS failures.
   An access log showing only 401 cannot distinguish those from a missing bearer.
   This PR adds fixed server-only categories and generated request IDs.
2. **Incomplete tool metadata, confirmed:** main advertises no explicit tool
   annotations or per-tool OAuth scopes. This PR marks eleven tools read-only,
   `show` as a write, and all HTTP tools as OAuth-protected with `mcp:tools`.
   Missing metadata is a compatibility concern; its causation of the reported
   ChatGPT installation failure is **not established**.
3. **Deployment provenance gap, confirmed:** main's health response contains no
   version. The reported Render commit matches GitHub, but public probes cannot
   independently prove the running revision. This PR exposes only a validated
   40-hex `RENDER_GIT_COMMIT` when Render supplies it automatically.
4. **Reauthorization blocker, reproduced with a synthetic hint:** Scalekit rejects
   an invalid hint before MCP. It is unknown whether the real hint failed because
   of issuer/client binding, token validity/signature, provider policy, or a
   ChatGPT/Scalekit interoperability defect. Neither clearing cookies nor
   disconnecting/reinstalling established the underlying cause. Do not label it
   “a cache problem” without the provider's rejection reason.
5. **Origin restriction, confirmed but not proven causal:** an otherwise valid
   local request with `Origin: https://chatgpt.com` is rejected with 403. Requests
   without Origin and with the configured service origin succeed. We have no
   evidence that ChatGPT's server-to-server request sends that Origin; this would
   not explain the historical 401. No Origin was added to the allowlist.

`Authentication succeeded, action discovery failed` locates a failure after the
platform's authorization stage, not a particular JWT claim. Possibilities include
bearer delivery/validation, scope, transport headers, initialization, tool metadata,
or platform import. Historical 401s occurred before the user's configuration
update and were not correlated with a new authenticated request.

“Missing OAuth callback data” may follow an OAuth error callback; it is not proof
that the configured redirect URI is wrong. “Unable to update this plugin” is a
generic platform failure. Neither message identifies a repository fix without the
corresponding platform/provider trace. No matching new backend logs were available
to this audit; the user's report of absent logs is not proof of no request.

## Code/security review

- Both `python server.py` and `asgi:app` build the complete root ASGI app after all
  routes/tools are registered. `/mcp` is an internal route, not a second mount.
  The SDK lifespan owns the Streamable HTTP session manager.
- `HOST`/`PORT` are used; Render terminates HTTPS. Stateless HTTP removes affinity
  and cross-request session-ID requirements. Auth remains required on every MCP
  request, including initialize and tools/list.
- JWT verification remains RS256-only, fixed administrator JWKS, exact issuer,
  configured audience, required exp/iat/sub/iss/aud, subject allowlist, and
  `mcp:tools`. Verified audience maps to the canonical MCP resource before the
  SDK's additional resource check. No unverified claim selects keys or trust.
- An ID token identifies a login to an OAuth client; it is not the access token
  for this MCP resource. A consent row does not prove access-token claims match.
  The resource server does not receive or validate `id_token_hint` and should not
  proxy authorization or strip hints to hide provider errors.
- The SDK supplies bearer 401 and insufficient-scope 403. The PR additionally
  includes `scope="mcp:tools"` in those challenges; the metadata URL and response
  statuses remain unchanged. Detailed rejection reasons stay in private logs.
- Pure ASGI diagnostic middleware does not read request bodies or buffer SSE.
  It logs a generated ID, HTTP method/status, fixed auth category, Origin presence
  (not its value), and elapsed time to response headers. No claims, tokens,
  incoming request IDs, query strings, or exception strings are included in these
  diagnostic records. Do not enable HTTP header/body debug logging.
- All twelve business functions, signatures and descriptions were AST-compared
  to main and are unchanged. `show` still writes a snapshot to GitHub; actual
  weather, Windy, Movebank and GitHub results depend on their own services and
  configured credentials/permissions. HTML returned by `show` is not a registered
  ChatGPT UI component; image display is a separate client concern, not discovery.
- Direct dependencies remain pinned: mcp 1.30.0, httpx 0.28.1, PyJWT 2.15.1.
  `pip check` passed; `pip-audit -r requirements.txt` audited 29 resolved packages
  and reported no known vulnerabilities. This is not a guarantee against unknown
  vulnerabilities. Transitive versions may vary between deployments.

## Tests and limits

Baseline: **33 passed**. Updated suite: **42 passed**.

| Level | Result | Explicit limitation |
| --- | --- | --- |
| JWT/security regressions | Signature, issuer/audience, expiry, scope, whitelist, JWKS errors rejected | Locally generated RSA tokens; no Scalekit user grant |
| Actual production ASGI routes | Health, discovery, anonymous rejection, authenticated RPC | In-process ASGI |
| Official SDK client over real TCP/Uvicorn | initialize, initialized notification, tools/list (12), all 12 tools/call passed | JWKS delivery and business APIs use fixtures; no real GitHub write |
| Tool schemas/results | Names, JSON Schemas, OAuth metadata, read/write hints, declared output schemas checked; invalid arguments rejected | No ChatGPT model/tool-import execution |
| Protocol/header checks | 2025-03-26, 2025-06-18, 2025-11-25; correct Accept/Content-Type; no session ID needed | ChatGPT's actual headers unavailable |
| Access-token replacement | Same SDK connection accepts replacement valid access token | Simulates replacement, not the provider refresh grant |
| Safe diagnostics | Parallel request isolation, correct 401/403 classification, no token/claim leakage in new records | Needs an approved deployment to observe real failures |
| Local MCP + actual Open-Meteo | weather_at succeeded through SDK with live weather data | Local test JWT, not Render or ChatGPT |
| Public production HTTP/OAuth | See live evidence above | Login/consent, valid code exchange, refresh and actual tools/list on Render not completed |

Reproduce automated checks:

```sh
python -m pip install -r requirements.txt pytest pytest-asyncio
python -m pytest -q
```

## Remaining access and acceptance steps

Do not repeat the environment-value checklist: the user already confirmed issuer,
audience, JWKS URL and resource URL, and identified the whitelist's user-ID source.
Do not send real tokens, callback URLs, HAR files containing credentials, or secrets
in chat/PRs. The missing capability is interactive login and trace access, not an
invitation to disclose credentials.

1. A real user must complete login/consent in an interactive OAuth client (MCP
   Inspector or a controlled browser), using the existing allowed identity. An
   independently authorized client must then initialize, list 12 tools and call
   weather_at on Render. Keep tokens inside that client. This separates the
   resource-server result from ChatGPT's account-link/import behavior.
2. If reauthorization still rejects `id_token_hint`, inspect the actual rejected
   authorize request in Scalekit's administrative trace/support tooling. Ask for
   the **rejection category** (issuer/client binding, signature, validity or policy)
   and correlation ID only. A successful-login-only log view may miss this error.
   A real successful grant is needed to test ID-token reuse and refresh; synthetic
   failure reproduction does not replace that test.
3. If this PR is approved for merge/deployment, verify `/healthz` revision against
   Render's deployed commit. Then one ChatGPT attempt should be correlated with
   the new `mcp_http` records: `missing_bearer`, `issuer_mismatch`,
   `audience_mismatch`, `subject_not_allowed`, `insufficient_scope`,
   `jwks_unavailable`, or `verified` plus HTTP status. No approval to deploy was
   assumed during this audit.
4. ChatGPT must import the 12-tool list and invoke them in a new conversation.
   Start with weather_at, then camera and permitted animal tools. Calling show
   performs a real GitHub write; confirm that action in ChatGPT. Missing business
   service credentials/Movebank study consent are separate from OAuth discovery.
   If independent MCP succeeds but ChatGPT fails, provide OpenAI Support the
   time/timezone, plugin name, public URL, displayed error, and correlation IDs.
   Do not repeatedly reinstall or create more clients without new evidence.

Minimal additional capability for autonomous completion: an available interactive
browser the user can sign into (ChatGPT and the Scalekit login/admin pages), plus
read-only Render deployment/log access. This session has neither a callable
browser interaction tool nor those administrative connectors/credentials.

## Official references checked

- [OpenAI authentication, reauthorization and callback issuer](https://developers.openai.com/plugins/build/auth)
- [OpenAI MCP metadata and tool annotations](https://developers.openai.com/plugins/build/mcp-server)
- [OpenAI custom MCP connection and acceptance tests](https://developers.openai.com/plugins/deploy/connect-chatgpt)
- [Scalekit MCP troubleshooting and resource issuer](https://docs.scalekit.com/authenticate/mcp/troubleshooting/)
