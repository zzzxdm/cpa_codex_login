# CPA Codex OAuth Helper

这是一个独立的 Python 服务，通过 CPA v8 Management API 检测和创建 Codex OAuth 凭据。CPA 可以部署在本机，也可以是远程地址。

配置文件只保存 CPA 和服务端设置，账号单独放在 `accounts.txt`，每行格式为：

```text
邮箱----密码----TOTP密钥
```

复制示例：

```bash
cp config.example.json config.json
cp accounts.example.txt accounts.txt
```

管理页面需要管理员密码。推荐在工具目录 `.env` 中设置 `ADMIN_PASSWORD`，它会覆盖 `config.json` 的 `server.admin_password`：

```bash
ADMIN_PASSWORD=设置一个强密码
```

服务启动时必须配置管理员密码；访问首页会先进入登录页。登录成功后使用有效期 12 小时的 HttpOnly、SameSite=Strict 会话 Cookie，退出登录立即失效，重启服务后需要重新登录。连续输错 3 次后冷却 1 分钟，冷却后每次再次输错依次冷却 3 分钟、10 分钟、1 小时、24 小时，之后维持 24 小时。冷却中不接受登录且不会因重复请求延长时间；状态统一按管理员账户累计，保存在 `data/admin_auth.json`，重启继续生效，成功登录后清零。账号列表、认证、删除、日志和设置接口都需要登录。HTTPS 反向代理应保留原始 Host 并设置 `X-Forwarded-Proto: https`，以启用 Secure Cookie。

登录页提供“记住密码”，默认不勾选；只在登录成功后保存，并在下次登录时自动填充。密码使用 AES-GCM 加密后保存在当前浏览器，密钥以不可导出的 CryptoKey 存入 IndexedDB；取消勾选立即清除密文。该功能需要 HTTPS 或 localhost 安全上下文，普通远程 HTTP 地址会禁用此选项。保存的密码不会绕过登录验证或冷却限制，也不会随请求日志输出。

账号行操作提供“删除”，只删除对应 CPA 凭证并保留账号配置。批量删除必须先勾选，支持跨页多选、全选当前页、全选筛选结果、清空选择。未选择账号时不会执行删除；删除成功后暂停对应账号的自动重认证，防止凭证被立即重新创建。

`config.json` 中设置 CPA 地址、管理密钥和 `accounts_file`。CPA 地址会自动选择连接方式：本机、内网 IP、内网 DNS 和 `host.docker.internal` 使用直接 HTTP；公网域名或公网 IP 使用浏览器打开 `management.html`，再通过同源 `fetch` 调用 CPA API，以复用 Cloudflare 浏览器会话。

2FA 配置位于 `config.json` 的 `two_factor`。默认 `mode: local` 使用账号配置中的 TOTP 密钥在本地生成验证码，不依赖外部服务；`page_url` 和 `api_url` 已预置 2FA 服务地址及接口，切换为 `mode: api` 后会按 `method` 请求接口。URL、POST body、请求头都支持 `{SECRET_KEY}` 或 `{secret}` 占位符，响应验证码字段由 `code_field` 指定，例如：

```json
"two_factor": {
  "mode": "api",
  "page_url": "https://2fa.kim/",
  "api_url": "https://2fa.kim/api/2fa={SECRET_KEY}",
  "method": "GET",
  "code_field": "code",
  "request_body": {},
  "headers": {},
  "timeout": 10
}
```

API 模式会把 TOTP 密钥发送给配置的接口；如果服务端和网络允许，推荐继续使用 `local` 模式以避免把密钥交给第三方。
工具只读取 `accounts.txt` 中列出的账号；页面保存账号时也会更新这个文件。

远程 CPA 的浏览器会话在一个专用线程中复用，供状态刷新、OAuth、回调和删除请求使用。Docker/Linux 使用 Xvfb 时不显示窗口；macOS 使用可见的本机 Chrome。域名是否属于内网按 DNS 解析结果判断，并不要求两个服务在同一台机器。

自动重新认证开关默认关闭；打开后，后端每 60 秒检查全部配置账号，发现 missing/invalid 凭据后加入现有并发池，跳过 deleted/error/paused 等异常账号。额度耗尽或管理员停用不会触发重新认证。关闭页面后检测仍继续。开关与异常账号状态保存在 `data/state.json`，Compose 已挂载 `./data:/app/data`，重启后保留。手动删除 CPA 凭证的账号会暂停自动认证，避免刚删完又被自动登录；可以手动认证恢复。

批量 OAuth 认证默认同时运行 4 个账号，每个账号的浏览器上下文和 OAuth state 相互独立。在 `config.json` 顶层设置并发数（整数 1–32）：

```json
{
  "auth_concurrency": 4,
  "auto_reauth": false,
  "auto_reauth_interval": 60
}
```

单账号和批量认证共用这个任务池，等待空位的账号显示“排队中”。失败或已删除账号不会阻塞其他任务；CPA API 的浏览器会话仍单独串行处理，以保证线程安全。修改配置后重启服务；Docker 执行 `docker compose up -d --build`。

验证账号并发调度：

```bash
python3 -m unittest -v tests.test_batch_concurrency
```

界面使用 CPA 风格的侧栏、状态统计和账号表格。连接 CPA、翻页和批量操作时显示 loading；默认每页 10 条，可选 20/50/100/200/500。搜索及状态筛选作用于全部配置账号。当前页的正常或额度不可用账号会通过 CPA 的 `/v8/management/requests/api-call` 查询 Codex 额度，后台最多 4 个任务，结果缓存 2 分钟，避免阻塞列表和重复查询。凭据 token 由 CPA 在服务端替换，工具不下载 token。查询中显示提示，完成后页面自动更新；查询失败时显示错误并保留历史观测，60 秒后允许重试，不会因此删除凭据或触发重认证。月、周和 5 小时窗口显示实际重置日期及剩余天数/小时，不使用订阅或 OAuth token 过期时间冒充额度重置时间。

测试页面后端、分页和自动重新认证：

```bash
python3 -m unittest -v tests.test_dashboard tests.test_batch_concurrency tests.test_quota tests.test_dashboard_browser tests.test_admin_auth tests.test_deletion tests.test_admin_browser tests.test_two_factor
```

测试 CPA transport：

```bash
python3 -m unittest -v tests.test_cpa_transport
```

该测试覆盖内外网地址判断、同源保护、浏览器会话复用、并发请求串行化和 callback/delete API 请求。

测试 CPA API：

```bash
python3 -m unittest -v tests.test_cpa_api
```

测试会读取 `.env` 中的 `CPA_URL` 和 `CPA_MANAGEMENT_KEY`，并区分 CPA 的 401/403 与远端 Cloudflare/WAF 的 403。

单独测试正式客户端的自动连接方式（读取 `.env`）：

```bash
python3 -m unittest -v tests.test_cpa_api.CPAAPITest.test_management_credentials_auto_transport
```

单独测试 Chrome 页面内的同源 API 请求：

```bash
CPA_BROWSER_CHANNEL=chrome CPA_BROWSER_HEADLESS=0 \
python3 -m unittest -v tests.test_cpa_api.CPAAPITest.test_management_credentials_via_browser_session
```

该测试只读取凭据列表，不修改 CPA 凭据；使用独立浏览器会话，完成后关闭浏览器。普通 HTTP 测试仍保留，运行整个测试文件时可对比两种方式。


本机运行：

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
python3 app.py --config ./config.json
```

打开 `http://127.0.0.1:8765/`。页面提供账号保存、CPA 状态刷新、单账号登录/重认证、批量认证、批量删除 CPA 凭证、额度概览和实时日志。批量认证按配置的并发数同时处理未认证账号，默认 4 个并发，跳过正常、已删除和正在认证的账号。账号列表支持分页，每页可选 10/20/50/100/200/500 条。批量删除只处理 `accounts.txt` 中配置账号对应的 CPA 凭证。若 OpenAI 在 OTP 后返回“账号已被删除或停用”，工具会立即停止该账号流程，并把页面状态标记为 `账号已删除`。点击登录后任务在后台执行，日志每秒刷新；浏览器会打开 OpenAI OAuth 页面，TOTP 在本地生成。遇到 CAPTCHA 或额外验证时需要人工处理。

也可以把变量写入工具目录下的 `.env`：

```bash
cp .env.example .env
# 编辑 .env
```

Docker Compose 会自动读取 `.env`；本机执行 `python app.py` 时，程序也会自动读取同目录 `.env`。命令行已经设置的环境变量优先于 `.env`。

Docker 部署支持环境变量覆盖配置文件：

```bash
CPA_URL=http://远程CPA地址:8317 \
CPA_MANAGEMENT_KEY=你的CPA管理密码 \
ADMIN_PASSWORD=本系统管理员密码 \
docker compose up -d
```

环境变量优先级高于 `config.json`：

- `CPA_URL` 覆盖 `cpa.url`；
- `CPA_MANAGEMENT_KEY` 覆盖 `cpa.management_key`。
- `ADMIN_PASSWORD` 覆盖 `server.admin_password`，这是本系统管理页面密码，不是 CPA 管理密钥。

Docker 部署：

```bash
cp config.example.json config.json
# 编辑 config.json，设置远程 CPA 地址、管理密钥和账号
# Docker 服务器使用默认的 `browser.mode=headless` 和 `browser.channel=chromium`
docker compose build
docker compose up -d
```

然后访问 `http://服务器地址:8765/`。认证使用 Xvfb 虚拟显示器运行 headed Chromium，避免纯 headless 浏览器被 Cloudflare 拦截。建议只在内网开放此端口，或通过 HTTPS 反向代理保护；配置文件包含账号密码、TOTP 密钥和 CPA 管理密钥，不要提交到 Git。
