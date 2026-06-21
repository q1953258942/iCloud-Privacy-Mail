# iCloud Privacy Mail 取码平台

独立项目，用来管理 iCloud 隐私邮箱 API 地址，并给注册项目提供取验证码接口。

当前版本：

- 支持本地 Web 面板。
- 支持录入 iCloud 账号标签。
- 支持手动导入已经创建好的隐私邮箱。
- 支持 Go 后端 Apple SRP 协议登录 iCloud，收到 2FA 后直接保存本地登录态。
- 支持通过比特浏览器手动登录 iCloud 后保存本地登录态。
- 支持协议调用 iCloud Hide My Email `generate + reserve` 创建隐私邮箱。
- 支持纯 Go 协议同步 iCloud Mail `mccgateway` 邮件服务并提取验证码，取码时不依赖浏览器页面执行脚本。
- 支持手动检测 iCloud Mail 登录态，并可在面板设置每隔几分钟自动检测一次。
- 支持为每个隐私邮箱生成独立 API 地址。
- 支持导入邮件测试数据。
- 支持从邮件标题/正文提取 6 位验证码。
- 支持对外提供取码 API。
- 支持管理接口 Admin Key、外部健康检查、自动取号接口。

## 启动

```powershell
go run ./cmd/panel --host 127.0.0.1 --port 8787
```

浏览器打开：

```text
http://127.0.0.1:8787/
```

## 配置

复制示例：

```powershell
Copy-Item .\config.example.json .\config.json
```

字段：

| 字段 | 说明 |
| --- | --- |
| `host` | 监听地址，默认 `127.0.0.1` |
| `port` | 监听端口，默认 `8787` |
| `data_path` | 本地状态文件，默认 `data/state.json` |
| `api_key` | 全局 API Key，可留空；每个邮箱也会自动生成独立 key |
| `admin_key` | 管理接口 Admin Key，可留空；部署到服务器时建议必填 |
| `public_base_url` | 对外复制 API 地址使用的公网 Base URL，可留空自动用当前访问地址 |
| `bit_browser_api` | 比特浏览器本地 API，默认 `http://127.0.0.1:54345` |
| `bit_browser_id` | 固定比特浏览器窗口 ID，可留空自动新建 |
| `icloud_login_url` | 手动登录打开地址，默认 `https://www.icloud.com.cn/icloudplus/` |
| `icloud_default_host` | 保存登录态时校验用 iCloud host，默认 `www.icloud.com.cn` |
| `icloud_client_id` | Apple Web OAuth 公共 Client ID；默认使用当前 iCloud Web 公开 widget key，通常不用改 |

`config.json`、`data/`、`logs/`、`captures/` 默认不会提交 Git。

部署到服务器时建议至少配置：

```json
{
  "host": "0.0.0.0",
  "port": 8787,
  "api_key": "CHANGE_ME_GLOBAL_API_KEY",
  "admin_key": "CHANGE_ME_ADMIN_KEY",
  "public_base_url": "https://your-domain.example"
}
```

说明：

- `api_key`：给外部项目调用健康检查/自动取号时使用；单个邮箱仍有独立 `mailbox_key`。
- `admin_key`：保护面板管理接口。前端 `服务配置` 里填写后会保存到本机浏览器 `localStorage`，不会写入服务端。
- `public_base_url`：复制出来的邮箱 API 地址会使用这个域名，方便发给其他项目或部署到公网。

## 使用流程

### 方式一：协议登录 + 协议创建隐私邮箱

1. 在面板 `1. 保存登录态` 输入 Apple ID 和密码，点击 `协议登录`。
2. 后端会按 Apple SRP 流程请求 `signin/init` 和 `signin/complete`；密码只在本机进程内参与 SRP 计算，不写入日志和 `data/state.json`。
3. 如果 Apple 要求 2FA，受信任设备允许后，把 6 位验证码填入面板，点击 `提交 2FA`。
4. 验证通过后，后端调用 `2sv/trust`、`accountLogin` 和 `setup/ws/1/validate` 生成本地 iCloud 登录态。
5. 确认账号具备 iCloud+ / Hide My Email 权限。
6. 保存成功后点击 `协议创建邮箱`，后端会调用：
   - `POST /v1/hme/generate`
   - `POST /v1/hme/reserve`
7. 面板支持填写 `总数` 和 `并发` 批量创建；总数大于 1 时会给标签自动追加序号，例如 `UPI-70-13-01`。建议先用 1-3 并发测试，避免 iCloud 临时限流。
8. 创建成功的邮箱会自动写入本地邮箱列表，并生成独立 API 地址。
9. 收到验证码邮件后，取码 API 会用 Go 后端纯协议同步 iCloud 邮件并提取 6 位验证码；也可以在面板点击 `同步邮件` 手动触发。
10. 面板 `检测登录态` 会请求 iCloud Mail 文件夹列表确认登录态是否还能同步；勾选 `开启自动检测` 后，会按填写的分钟间隔循环检测，失败时日志会提示重新协议登录或保存登录态。

### 方式二：浏览器兜底登录 + 协议创建隐私邮箱

如果 Apple 当前风控不允许 SRP 协议登录，可展开 `浏览器兜底 / 高级连接参数`：

1. 启动比特浏览器本地服务。
2. 点击 `打开登录窗口`。
3. 在打开的窗口里手动登录 iCloud。
4. 回到面板点击 `保存登录态`。这一步只读取当前窗口 Cookie，并由 Go 后端直接请求 `setup/ws/1/validate` 校验登录态。
5. 后续创建邮箱和取码仍然走 Go 后端协议。

### 方式三：手动导入已有隐私邮箱

1. 在外部 iCloud/隐私邮箱平台创建好邮箱。
2. 在本项目面板里添加 iCloud 账号标签。
3. 导入隐私邮箱，例如 `alias@icloud.com`。
4. 面板会生成 `API 地址`。
5. 注册项目使用这个 API 地址取验证码。

## iCloud 登录态保存

登录态保存流程只保存到本地 `data/state.json`，该目录默认被 `.gitignore` 排除。

前端返回只显示脱敏状态：

- Apple ID 掩码
- DSID 掩码
- Cookie 数量
- iCloud+ / Hide My Email 权限状态
- `premiummailsettings` 服务地址
- `mccgateway` 邮件同步服务地址
- `mail` 服务地址

不会把 Cookie、Session、Token 原文返回给前端或写入日志。

相关接口：

```http
POST /api/icloud/protocol-login/start
POST /api/icloud/protocol-login/2fa
POST /api/icloud/browser/open
POST /api/icloud/session/save
POST /api/icloud/session/check
GET  /api/icloud/session
POST /api/icloud/mailboxes/create
```

登录态过期、iCloud 权限变化或 Apple 要求重新验证时，`POST /api/icloud/session/check` 会返回失败，并把最近检测结果写入本地状态；优先重新走协议登录，如果 Apple 风控拦截，再用浏览器兜底登录保存 Cookie。

## 对外取码 API

按邮箱取码：

```http
GET /api/v1/mailboxes/{email}/code?key=<mailbox_key>&after=<RFC3339>
```

按邮箱 ID 取码：

```http
GET /api/mailboxes/{id}/code?key=<mailbox_key>&after=<RFC3339>
```

可选参数：

| 参数 | 说明 |
| --- | --- |
| `key` | 必填；单邮箱 key 或全局 `api_key` |
| `after` | 建议必填；只接受这个时间之后的新邮件，避免拿旧验证码 |
| `keyword` | 邮件关键词，默认 `OpenAI` |
| `allow_stale` | 可选；填 `1/true` 时允许 iCloud 同步失败后回退返回本地缓存旧码，默认不允许 |

成功：

```json
{
  "success": true,
  "email": "alias@icloud.com",
  "code": "123456",
  "subject": "Your OpenAI code is 123456",
  "received_at": "2026-06-21T12:00:00+08:00",
  "message_id": "msg_000001"
}
```

暂未收到：

```json
{
  "success": false,
  "code": "no_code",
  "message": "暂未收到验证码",
  "retryable": true
}
```

取码时服务端会先用保存的 Cookie 直接请求 iCloud Mail 协议接口同步邮件，再查本地已入库验证码邮件。默认不会在同步失败时把本地旧验证码当作新验证码返回；确实需要调试旧缓存时再加 `allow_stale=1`。

## 外部项目 API

### 健康检查

```http
GET /api/v1/health
Authorization: Bearer <api_key>
```

返回：

```json
{
  "success": true,
  "service": "icloud-privacy-mail",
  "api_active": true,
  "icloud_active": true,
  "time": "2026-06-21T12:00:00+08:00"
}
```

### 自动取号

自动取号需要配置全局 `api_key`。

```http
POST /api/v1/mailboxes/claim
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "project": "openai",
  "purpose": "register",
  "count": 1
}
```

返回一个 `status=available` 且 `api_active=true`、`icloud_active=true` 的邮箱，并自动标记为 `used`，避免并发重复领取：

```json
{
  "success": true,
  "mailbox": {
    "email": "alias@icloud.com",
    "api_url": "https://your-domain.example/api/v1/mailboxes/alias%40icloud.com/code?key=...",
    "api_active": true,
    "icloud_active": true,
    "status": "used"
  }
}
```

如果没有可用邮箱：

```json
{
  "success": false,
  "code": "no_available_mailbox",
  "message": "没有可用隐私邮箱",
  "retryable": false
}
```

## 管理接口

如果配置了 `admin_key`，除以下对外接口外，所有 `/api/` 管理接口都需要 Admin Key：

- `GET /`
- `GET /api/v1/health`
- `POST /api/v1/mailboxes/claim`
- `GET /api/v1/mailboxes/{email}/code`
- `GET /api/mailboxes/{id}/code`

请求头任选一种：

```http
X-Admin-Key: <admin_key>
Authorization: Bearer <admin_key>
```

面板里可直接在 `服务配置 -> Admin Key` 填写。

## 邮件同步

同步入口：

```http
POST /api/mailboxes/{id}/sync?keyword=OpenAI
X-Admin-Key: <admin_key>
```

同步逻辑：

1. 使用保存的 iCloud Cookie 和 `setup/ws/1/validate` 得到的服务地址。
2. 调用 iCloud Mail `mccgateway` 邮件接口读取 Inbox/分类文件夹最近线程。
3. 按隐私邮箱别名匹配收件人。
4. 只把能提取到 6 位 OTP 的邮件写入本地 `data/state.json`。
5. 使用 iCloud 远端消息 ID 去重，重复同步不会重复增加收件数。

同步邮件和对外取码全程由 Go 后端直接请求 iCloud 协议接口；比特浏览器只用于人工登录和保存 Cookie，不参与邮件读取。

## 当前限制

- Apple SRP 协议登录依赖 iCloud Web 当前公开接口；Apple 风控、地区端点或安全策略变化时可能需要临时使用浏览器兜底。
- 2FA pending 登录态只保存在进程内，服务重启后需要重新发起协议登录。
- 登录态可能过期；过期后需要重新协议登录或浏览器兜底保存。
- 邮件同步依赖 iCloud 网页服务接口和当前登录态；Apple 页面/接口变化时需要重新适配。
- iCloud Cookie 属于敏感数据，只能保存在本机 `data/`，不要打包给别人。
- 对外部署时不要把管理面板裸露在公网；至少配置 `admin_key`，并优先通过反向代理加 HTTPS。

## 后续实现顺序

1. 增加登录态自动检测和过期提示。
2. 增加批量创建队列。
3. 增加账号登录态状态：`need_login`、`need_2fa`、`no_icloud_plus`、`rate_limited`。
4. 给主注册项目新增 `icloud_api` 邮箱来源。
