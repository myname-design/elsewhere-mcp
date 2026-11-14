# Scalekit、Render 与 ChatGPT

## Scalekit 配置

本项目继续使用 MCP Python SDK 和 PyJWT，通过 Scalekit 的公开 JWKS 本地验证令牌。
无需安装另一套 FastMCP 框架，也无需在 MCP 服务器保存 Scalekit API client secret。
现有 12 个摄像头、天气和动物追踪工具保持原样。

在 Scalekit Dashboard > MCP Servers 创建或选择对应的 MCP server：

1. 将 Server URL 设置为完整的 https://your-service.onrender.com/mcp，和 MCP_RESOURCE_URL 一致。
2. 在该 MCP server 配置中添加 mcp:tools scope；不要改为其他名称或取消服务器校验。
3. 根据 ChatGPT 连接方式开启 CIMD 或 DCR，确认资源专属授权服务器元数据公布相应能力。
   使用自动注册时不要填写 Scalekit 的管理 API Client ID/secret。
   使用预注册客户端时，凭据和准确回调 URL 必须来自同一 MCP server 的客户端配置。
4. 配置用户登录方式，并取得自己登录后的稳定 sub。它必须加入 OAUTH_ALLOWED_SUBJECTS；
   能在 Scalekit 登录并不代表有权限使用本服务器。不要用 email、res_... 或 OAuth Client ID 代替 sub。
   如需检查令牌声明，在本地安全地检查；不要将真实 access/refresh token 发到在线解码器或日志。
5. 对旧工作区，如 Dashboard 显示 Resource bound issuer，先按官方迁移指南启用；
   然后断开并重新授权 ChatGPT，丢弃旧 issuer 的令牌。本项目只信任明确配置的单个 issuer，
   不自动接受旧环境级 issuer，也不提供免认证迁移窗口。

假设环境 URL 是 https://your-environment.scalekit.com，Resource ID 是 res_your_resource_id：

| 项目 | 配置 / 含义 |
| --- | --- |
| OAUTH_ISSUER_URL | https://your-environment.scalekit.com/resources/res_your_resource_id；精确匹配 iss，不额外加尾部斜杠 |
| OAUTH_AUDIENCE | res_your_resource_id；来自 MCP server 的 Resource ID，不是 Client ID |
| OAUTH_JWKS_URL | https://your-environment.scalekit.com/keys；以该资源发现文档中的 jwks_uri 为准 |
| MCP_RESOURCE_URL | https://your-service.onrender.com/mcp；对外资源标识，不与 res_... 混用 |
| OAUTH_ALLOWED_SUBJECTS | 自己的稳定 sub，多个用户用逗号分隔；空白名单拒绝启动 |

Scalekit token 的 aud 可以是字符串或数组；必须包含配置的 OAUTH_AUDIENCE。
当 Scalekit 配置了 Server URL，aud 还可能同时包含 MCP URL。本项目不要求数组的顺序，
但不会在 res_... 校验失败时退回只检查 URL，也不根据未验证 token 选择 issuer 或 JWKS。
SDK 的 AccessToken.resource 只在 JWT audience 验证成功后映射为配置的 MCP_RESOURCE_URL，
继续启用 validate_token_resource；这个映射不是跳过 JWT audience 检查。

### OAuth 发现

- /.well-known/oauth-protected-resource/mcp：SDK 提供的规范发现地址，401 的 WWW-Authenticate 指向这里。
- /.well-known/oauth-protected-resource：兼容 Scalekit 指南的根地址，返回相同 JSON。
- resource 为 MCP_RESOURCE_URL，authorization_servers 只包含配置的资源专属 issuer，
  scopes_supported 为 mcp:tools，bearer_methods_supported 为 header。
- 授权服务器元数据、authorize、token、客户端注册和刷新均由 Scalekit 提供；
  本地不伪造 /.well-known/oauth-authorization-server 或注册端点。
- 必须使用资源专属授权服务器发现信息；只使用环境级 OIDC 信息可能缺少 DCR 注册端点。

官方资料：
[Scalekit MCP Quickstart](https://docs.scalekit.com/authenticate/mcp/quickstart/)、
[issuer 与 audience 排错](https://docs.scalekit.com/authenticate/mcp/troubleshooting/)、
[资源专属发现和 JWKS](https://docs.scalekit.com/authenticate/mcp/xmcp-quickstart/)、
[旧 issuer 迁移](https://docs.scalekit.com/authenticate/mcp/migrate-to-2026-07-28-mcp-spec/)。

## 认证架构

服务使用 MCP Python SDK 的 Streamable HTTP（/mcp），作为 OAuth 资源服务器。
外部 OAuth 提供方负责登录、用户同意、授权码、PKCE S256、刷新与客户端注册。
本仓库不自建密码登录或授权服务器。不能只配置一个 API key 就完成 ChatGPT OAuth。

选择支持 MCP/OAuth 2.1 的提供方，并配置：

- HTTPS issuer，以及可发现的 OAuth 授权服务器元数据（含 authorization_endpoint、token_endpoint、PKCE S256）。
- 为这个 MCP API 签发 RS256 access token（不是 ID token）；aud 必须包含 OAUTH_AUDIENCE，scope 必须含 mcp:tools。
  未设置 OAUTH_AUDIENCE 时保留原行为，检查 MCP_RESOURCE_URL；显式空值属于配置错误。
- token 必须有 iss、sub、iat、exp；只允许 OAUTH_ALLOWED_SUBJECTS 中列出的 sub 使用。
- 如提供方支持 RFC 8707 resource 参数，将其映射为这个 API 的 audience；不要让用户手动传入另一个服务的 token。
- 为 ChatGPT 注册 OAuth 客户端，回调 URL 使用 ChatGPT 创建连接时显示的值，严格匹配；
  如果 ChatGPT 当前界面支持填写 client ID/secret，填入该客户端凭据。
  否则提供方必须支持 ChatGPT 可用的动态客户端注册或客户端标识元数据发现。
  不支持这些能力的普通 OIDC 提供方不能直接接入。

JWKS 地址由管理员固定配置，不采信 token 中的 jku/x5u；只接受 RS256。
缺少认证配置时 HTTP 启动失败。所有 /mcp 方法都需要 Bearer access token。
两个资源发现端点和 /healthz 可公开访问，不包含工具或密钥。
stdio 只适用于受信任的本地进程，不提供远程认证。

## Render

从本 PR 分支创建 Blueprint（render.yaml），或创建 Python Web Service：

- Build: pip install -r requirements.txt
- Start: uvicorn asgi:app --host ${HOST:-0.0.0.0} --port ${PORT:-8787}
- Health check: /healthz
- 单进程运行，使用 stateless HTTP，避免跨请求会话依赖和重启丢失会话。

asgi:app 是明确的生产入口：先完成 server.py 中所有工具及自定义路由注册，再通过
create_http_app() 导出整个 Starlette 应用。该应用自带 MCP session manager lifespan，
必须挂在根路径 /；不要再将它 Mount 到 /mcp，否则会产生 /mcp/mcp 及错误的发现路径。
/mcp 是应用内部的 MCP 路由，不是整个应用的挂载前缀。

python server.py 仍受支持，HTTP 模式也通过同一个 create_http_app() 工厂运行；
TRANSPORT=stdio 继续用于本地客户端，不能通过 ASGI 工厂暴露成未认证的 HTTP。
不要启动低层 streamable_http handler 代替完整应用，它不包含健康检查和发现路由。

已存在的 Render 服务不一定自动应用仓库中的 render.yaml：
后续获准部署时，应在 Render Settings 核对 Start Command、Health Check Path=/healthz、
服务根目录、分支和部署提交。仅修改仓库配置不等于修改现有服务设置。

### 404 排查：应用路由与 Render 路由层

未登录时应得到以下响应（不需要在 URL 或请求头中放密钥）：

| 请求 | 期望响应 |
| --- | --- |
| GET /healthz | 200，JSON status=ok |
| GET /.well-known/oauth-protected-resource/mcp | 200，resource、authorization_servers、scopes_supported |
| GET /.well-known/oauth-protected-resource | 200，与上面的元数据一致 |
| GET /mcp | 401，WWW-Authenticate 包含规范元数据地址 |

可用 curl -i https://你的服务.onrender.com/healthz 查看状态和响应头。
如果出现 x-render-routing: no-server，先排查 Render 后端路由/服务关联，而不是绕过认证：
核对 Dashboard 的真实 Service URL、服务是否运行或暂停、最新部署状态、
Uvicorn 是否在 Render 提供的 PORT 上监听，以及请求是否出现在应用访问日志中。
记录响应头中的请求/路由信息、请求时间和部署提交，必要时联系 Render 支持。
这个响应头不能单独证明是哪项 Render 设置错误，ASGI 代码改动也不能保证修复该路由层状态。
如果部署显示 Live 但 /healthz 仍是 404，核对实际服务是否设置了上述健康检查路径。
应用内 404 则应核对实际运行入口和挂载前缀。不要用公开未认证的 /mcp 来掩盖发现失败。

| 环境变量 | 配置 |
| --- | --- |
| WINDY_API_KEY | 必填，Windy Webcams API key，Render secret |
| MCP_RESOURCE_URL | 必填，例如 https://your-service.onrender.com/mcp，与 Scalekit Server URL 一致，无尾部斜杠 |
| OAUTH_ISSUER_URL | 必填，提供方 issuer，精确匹配 token iss（包括尾部斜杠） |
| OAUTH_JWKS_URL | 必填，提供方公开 HTTPS JWKS 地址 |
| OAUTH_AUDIENCE | Scalekit 必填，当前 MCP 的 res_...；其他提供方省略时默认 MCP_RESOURCE_URL。Blueprint 要求填写时，其他提供方可明确填写 MCP URL |
| OAUTH_ALLOWED_SUBJECTS | 必填，授权用户的稳定 sub，逗号分隔 |
| HOST | 0.0.0.0，Blueprint 已设置 |
| PORT | Render 自动提供，代码读取，不需要手动固定 |
| TRANSPORT | streamable-http，Blueprint 已设置 |
| MOVEBANK_USER_B64 / MOVEBANK_PASS_B64 | 可选，保留动物追踪功能；用户名/密码的 base64 值，仍须作为 secret 管理 |
| GH_TOKEN / GH_REPO | 可选，show 上传截图所用 token 和公开仓库 owner/name |

GH_TOKEN 仅授予目标截图仓库 Contents 读写，不能复用部署凭据。
天气无须 API key；不配置 Movebank/GitHub 只会使对应工具提示缺少配置。
不要在代码、URL、命令行示例、工单或日志中粘贴真实密钥。
不要开启 HTTP header/body 调试日志。Render 终止 HTTPS，应用绑定内部 HTTP 端口。
域名变更时同步更新 MCP_RESOURCE_URL、Scalekit Server URL 和 ChatGPT 连接；
仍使用同一 Scalekit MCP server 时 res_... 不变。不关闭 DNS rebinding 保护。

## ChatGPT

1. 部署成功后检查 HTTPS /healthz 返回 200。
2. 在支持自定义 MCP 的 ChatGPT 工作区开启开发者模式，在 Apps/连接器中创建自定义 MCP 应用
   （入口名称取决于账户和工作区策略）。
3. MCP URL 填 https://your-service.onrender.com/mcp，选择 OAuth，
   根据 Scalekit 已开启的能力选择 CIMD/DCR，或使用同一资源下的预注册客户端，
   完成登录与授权。不要填写 Scalekit 管理 API 的 client secret。
4. 使用 OAUTH_ALLOWED_SUBJECTS 中的用户登录；验证能列出 12 个工具，尝试 weather_at，
   然后测试摄像头及已配置的 Movebank 工具。

不要选择 No authentication，也不要将密钥添加到查询参数。
ChatGPT 自定义 MCP 连接不等同于旧式插件 manifest 或 GPT Actions OpenAPI。
静态 Bearer header 不是这里的 ChatGPT 登录方案。

## 验证与运维

完整链路的已验证结果、未验证边界及后续验收见 [INTEGRATION_AUDIT.md](INTEGRATION_AUDIT.md)。
新增 `mcp_http` 日志只记录请求 ID、状态码和固定认证结果分类，不记录令牌或用户声明。
401 时可据此区分缺少 Bearer、issuer/audience 不符、白名单拒绝和 JWKS 故障；
403 时区分 scope 不足与已验签后的传输拒绝。Origin 白名单仍不放宽。
`/healthz` 在 Render 自动提供合法 `RENDER_GIT_COMMIT` 时返回 `revision`，无需新增 secret。
授权失败的详细分类仅用于服务端诊断，不会返回给未授权客户端。

运行 python -m pip install -r requirements.txt pytest pytest-asyncio，
再运行 python -m pytest -q；CI 使用同样步骤，无真实服务凭据。
测试覆盖 Scalekit 形式的签名 JWT、真实 JWKS 解析与缓存、issuer/audience、
拒绝匿名或非白名单用户、scope、MCP 初始化、两种发现端点及认证后工具调用。
测试只 mock JWKS HTTP 响应，不绕过这些集成测试中的 JWT 验证器。
路由回归还直接导入 asgi:app，通过应用自身的 lifespan 发送真实 ASGI 请求，
并在独立 Python 进程中启动 python server.py 和 uvicorn asgi:app，
验证真实监听端口上的健康、发现与 401 响应，避免只测路由函数或另一套测试专用应用。
第三方 API 通过 mock 回归；真实 Windy/Movebank/GitHub、Render TLS 与 ChatGPT OAuth
仍需在配置账户后做端到端验收。

移除某个 sub 并重新部署可撤销该用户访问；使用短有效期 access token。
JWKS 缓存最多 5 分钟，紧急撤销签名密钥时重启服务清除缓存。
已有用户的 token 在有效期内不会进行在线撤销检查。
