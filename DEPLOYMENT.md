# Render 与 ChatGPT

## 认证架构

服务使用 MCP Python SDK 的 Streamable HTTP（/mcp），作为 OAuth 资源服务器。
外部 OAuth 提供方负责登录、用户同意、授权码、PKCE S256、刷新与客户端注册。
本仓库不自建密码登录或授权服务器。不能只配置一个 API key 就完成 ChatGPT OAuth。

选择支持 MCP/OAuth 2.1 的提供方，并配置：

- HTTPS issuer，以及可发现的 OAuth 授权服务器元数据（含 authorization_endpoint、token_endpoint、PKCE S256）。
- 为这个 MCP API 签发 RS256 access token（不是 ID token）；aud 必须包含完整的 MCP_RESOURCE_URL，scope 必须含 mcp:tools。
- token 必须有 iss、sub、iat、exp；只允许 OAUTH_ALLOWED_SUBJECTS 中列出的 sub 使用。
- 如提供方支持 RFC 8707 resource 参数，将其映射为这个 API 的 audience；不要让用户手动传入另一个服务的 token。
- 为 ChatGPT 注册 OAuth 客户端，回调 URL 使用 ChatGPT 创建连接时显示的值，严格匹配；
  如果 ChatGPT 当前界面支持填写 client ID/secret，填入该客户端凭据。
  否则提供方必须支持 ChatGPT 可用的动态客户端注册或客户端标识元数据发现。
  不支持这些能力的普通 OIDC 提供方不能直接接入。

JWKS 地址由管理员固定配置，不采信 token 中的 jku/x5u；只接受 RS256。
缺少认证配置时 HTTP 启动失败。所有 /mcp 方法都需要 Bearer access token。
发现端点 /.well-known/oauth-protected-resource/mcp 和 /healthz 可公开访问，不包含工具或密钥。
stdio 只适用于受信任的本地进程，不提供远程认证。

## Render

从本 PR 分支创建 Blueprint（render.yaml），或创建 Python Web Service：

- Build: pip install -r requirements.txt
- Start: python server.py
- Health check: /healthz
- 单进程运行，使用 stateless HTTP，避免跨请求会话依赖和重启丢失会话。

| 环境变量 | 配置 |
| --- | --- |
| WINDY_API_KEY | 必填，Windy Webcams API key，Render secret |
| MCP_RESOURCE_URL | 必填，例如 https://your-service.onrender.com/mcp，与 OAuth audience 一致，无尾部斜杠 |
| OAUTH_ISSUER_URL | 必填，提供方 issuer，精确匹配 token iss（包括尾部斜杠） |
| OAUTH_JWKS_URL | 必填，提供方公开 HTTPS JWKS 地址 |
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
域名变更时同步更新 resource/audience 与 ChatGPT 连接；不关闭 DNS rebinding 保护。

## ChatGPT

1. 部署成功后检查 HTTPS /healthz 返回 200。
2. 在支持自定义 MCP 的 ChatGPT 工作区开启开发者模式，在 Apps/连接器中创建自定义 MCP 应用
   （入口名称取决于账户和工作区策略）。
3. MCP URL 填 https://your-service.onrender.com/mcp，选择 OAuth，
   按提供方配置填写客户端凭据（若界面提供），完成登录与授权。
4. 使用 OAUTH_ALLOWED_SUBJECTS 中的用户登录；验证能列出 12 个工具，尝试 weather_at，
   然后测试摄像头及已配置的 Movebank 工具。

不要选择 No authentication，也不要将密钥添加到查询参数。
ChatGPT 自定义 MCP 连接不等同于旧式插件 manifest 或 GPT Actions OpenAPI。
静态 Bearer header 不是这里的 ChatGPT 登录方案。

## 验证与运维

运行 python -m pip install -r requirements.txt pytest pytest-asyncio，
再运行 python -m pytest -q；CI 使用同样步骤，无真实服务凭据。
测试覆盖 JWT 校验、拒绝匿名访问、scope、MCP 初始化、发现端点和原工具注册。
第三方 API 通过 mock 回归；真实 Windy/Movebank/GitHub、Render TLS 与 ChatGPT OAuth
仍需在配置账户后做端到端验收。

移除某个 sub 并重新部署可撤销该用户访问；使用短有效期 access token。
JWKS 缓存最多 5 分钟，紧急撤销签名密钥时重启服务清除缓存。
已有用户的 token 在有效期内不会进行在线撤销检查。
