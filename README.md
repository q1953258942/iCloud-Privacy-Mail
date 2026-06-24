# iCloud Privacy Mail 取码平台

独立 Go 服务，用来登录 iCloud、创建 Hide My Email 隐私邮箱、同步验证码邮件，并给外部注册项目提供取码 API。

当前版本是 **全协议后端**：不依赖比特浏览器、CDP、浏览器页面脚本或手动复制 Cookie。

## 功能总览

- 账号密码注册/登录：第一个注册账号自动成为管理员，后续账号为普通用户。
- 管理员数据管理：管理员可查看所有用户、iCloud 登录态和隐私邮箱；普通用户只能操作自己的数据。
- Apple SRP 协议登录：后端发起 iCloud 登录，用户收到 2FA 后提交 6 位验证码保存登录态。
- 隐私邮箱创建：后端调用 iCloud Hide My Email `generate + reserve` 创建邮箱。
- 批量创建：支持设置总数、并发数和创建间隔秒；默认每创建一个等待 30 秒，创建结果写入服务器状态文件。
- 邮件同步：后端直接请求 iCloud Mail `mccgateway` 接口，同步最新验证码邮件。
- 取码 API：每个隐私邮箱自动生成独立 `mailbox_key` 和 API 地址。
- 自动取号 API：外部项目可用全局 `api_key` 领取可用邮箱，领取后自动标记为已使用。
- 登录态检测：可手动检测 iCloud Mail 是否还能同步，也可在前端开启定时检测。
- 数据导出：当前登录用户可导出自己有权访问的数据；管理员导出全量数据。

## 目录结构

```text
cmd/panel/                 Go 服务入口
internal/app/              后端业务、协议客户端、状态存储和模板
internal/app/templates/    前端页面模板
config.example.json        配置模板
README.md                  使用与部署说明
```

以下目录是运行或排障产物，默认被 `.gitignore` 排除，不应提交或打包给别人：

```text
bin/
dist/
data/
logs/
captures/
.anna_skills/
.anna_manifest_tmp.json
config.json
```

## 配置

复制配置模板：

```powershell
Copy-Item .\config.example.json .\config.json
```

配置字段：

| 字段 | 说明 |
| --- | --- |
| `host` | 监听地址，本地默认 `127.0.0.1`；服务器建议仍监听 `127.0.0.1`，由 Nginx/Caddy 反代 |
| `port` | 监听端口，默认 `8787` |
| `data_path` | 服务器状态文件，默认 `data/state.json` |
| `api_key` | 全局 API Key，用于健康检查和自动取号；管理面板不使用它登录 |
| `public_base_url` | 对外复制 API 地址用的公网地址，例如 `https://www.example.com` |
| `icloud_default_host` | iCloud 登录态校验 Host，默认 `www.icloud.com.cn` |
| `icloud_client_id` | iCloud Web 公共 Client ID，通常不用修改 |

示例：

```json
{
  "host": "127.0.0.1",
  "port": 8787,
  "data_path": "/opt/icloud-privacy-mail/shared/data/state.json",
  "api_key": "CHANGE_ME_GLOBAL_API_KEY",
  "public_base_url": "https://www.example.com",
  "icloud_default_host": "www.icloud.com.cn",
  "icloud_client_id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d"
}
```

> 管理面板只支持账号密码登录；旧版 Admin Key 管理入口已移除。

## 本地运行

```powershell
go run ./cmd/panel --config .\config.json
```

打开：

```text
http://127.0.0.1:8787/login
```

首次注册的账号自动成为管理员。

## 账号与权限

| 角色 | 权限 |
| --- | --- |
| 管理员 | 查看全部用户、全部 iCloud 登录态、全部隐私邮箱；可导出全量数据 |
| 普通用户 | 只能查看和操作自己创建的 iCloud 登录态和隐私邮箱；只能导出自己的数据 |

所有管理接口默认要求登录后的 HttpOnly Cookie。外部取码接口只接受单邮箱 `mailbox_key` 或全局 `api_key` 请求头，不接受全局 key 放在 URL 查询参数里。

## 使用流程

### 1. 登录 iCloud 并保存登录态

1. 进入 `/login` 注册或登录平台账号。
2. 进入首页，在 `保存登录态` 输入 Apple ID 和密码。
3. 点击 `协议登录`。
4. 如果 Apple 要求 2FA，在受信任设备允许后，把 6 位验证码填入面板。
5. 点击 `提交 2FA`。
6. 后端会完成 `2sv/trust`、`accountLogin` 和 `setup/ws/1/validate`，并把 iCloud Cookie 写入服务器 `data_path`。

密码只参与当前登录请求，不写入状态文件、不返回前端、不写日志。

### 2. 创建隐私邮箱

1. 登录态保存成功后，在 `协议创建邮箱` 区域填写标签、备注、总数、并发和创建间隔秒。
2. 点击创建。
3. 后端调用 iCloud Hide My Email 接口创建邮箱，并写入服务器状态文件。
4. 每个邮箱会生成独立 API 地址和 `mailbox_key`。

默认创建间隔为 `30` 秒；批量时即使设置并发，也会在前端按全局间隔节流，保证两次创建请求之间至少等待配置的秒数。建议先用 `总数=1，并发=1` 验证账号权限，再按 `30-60` 秒间隔慢速创建，避免 iCloud 临时限流。

### 3. 同步邮件和取验证码

- 面板可手动点击 `同步邮件`。
- 对外取码 API 会先尝试同步 iCloud 最新邮件，再从本地状态中提取最新 6 位验证码。
- 建议调用取码 API 时带 `after=<RFC3339>`，避免拿到历史旧码。

## 对外取码 API

### 按邮箱地址取码

```http
GET /api/v1/mailboxes/{email}/code?key=<mailbox_key>&after=<RFC3339>&keyword=OpenAI
```

### 按邮箱 ID 取码

```http
GET /api/mailboxes/{id}/code?key=<mailbox_key>&after=<RFC3339>&keyword=OpenAI
```

参数：

| 参数 | 说明 |
| --- | --- |
| `key` | 必填；单邮箱独立 key |
| `after` | 建议必填；只返回该时间之后的新验证码 |
| `keyword` | 邮件关键词，默认 `OpenAI` |
| `allow_stale` | 默认 false；只有排障时才建议打开，允许同步失败后回退本地缓存旧码 |

成功响应：

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

未收到响应：

```json
{
  "success": false,
  "code": "no_code",
  "message": "暂未收到验证码",
  "retryable": true
}
```

## 外部自动取号 API

自动取号使用全局 `api_key`，只接受请求头：

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

返回一个可用邮箱，并自动标记为 `used`，避免并发重复领取：

```json
{
  "success": true,
  "mailbox": {
    "email": "alias@icloud.com",
    "api_url": "https://www.example.com/api/v1/mailboxes/alias%40icloud.com/code?key=...",
    "api_active": true,
    "icloud_active": true,
    "status": "used"
  }
}
```

健康检查：

```http
GET /api/v1/health
Authorization: Bearer <api_key>
```

## 数据保存与导出

- 服务器真实数据只保存到 `config.json` 的 `data_path`。
- 前端不显示、不修改服务器数据目录。
- `导出数据` 会触发浏览器保存文件选择框；不支持 File System Access API 的浏览器会回退为默认下载。
- `导出邮箱API` 支持 `txt/csv/tsv/jsonl`，TXT 每行 `邮箱----API`，其他格式每行一条邮箱 API 记录。
- `只导出邮箱` 支持 `txt/csv/tsv/jsonl`，所有格式均保持一行一个邮箱记录。
- 普通用户只能导出自己的登录态和隐私邮箱；管理员可导出全量数据。
- 导出文件包含 iCloud Cookie 和邮箱 API token，属于敏感文件，不要发给无关人员。

## 服务器部署

推荐部署结构：

```text
/opt/icloud-privacy-mail/
  icloud-privacy-mail
  config.json
  shared/data/state.json
  backups/
```

构建 Linux amd64：

```powershell
$env:GOOS='linux'
$env:GOARCH='amd64'
$env:CGO_ENABLED='0'
go build -trimpath -ldflags="-s -w" -o .\dist\icloud-privacy-mail-linux-amd64 .\cmd\panel
```

systemd 示例：

```ini
[Unit]
Description=iCloud Privacy Mail
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/icloud-privacy-mail
ExecStart=/opt/icloud-privacy-mail/icloud-privacy-mail --config /opt/icloud-privacy-mail/config.json
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/opt/icloud-privacy-mail

[Install]
WantedBy=multi-user.target
```

Nginx 只反代当前服务端口即可，建议开启 HTTPS：

```nginx
server {
    server_name www.example.com;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

发布前后建议执行：

```powershell
go test ./...
go vet ./...
go build -trimpath -o .\bin\icloud-privacy-mail.exe .\cmd\panel
```

服务器验证：

```bash
systemctl is-active icloud-privacy-mail
curl -fsS http://127.0.0.1:8787/login >/dev/null
curl -fsSI https://www.example.com/login
```

## 安全注意

- 不要提交或打包 `config.json`、`data/`、`bin/`、`captures/`。
- 不要在 URL 里放全局 `api_key`；全局 key 只放 `Authorization` 或 `X-API-Key` 请求头。
- 单邮箱 `mailbox_key` 会出现在复制出来的取码 URL 中，泄露后该邮箱验证码可被读取。
- iCloud Cookie 和导出的状态文件是敏感数据，必须按账号隔离保存。
- 对外部署时务必使用 HTTPS，并限制服务器文件权限。

## 当前限制

- Apple/iCloud 网页协议可能变化；如果 Apple 风控、地区端点或接口参数变化，需要重新适配。
- 2FA pending 状态只保存在进程内；服务重启后需要重新发起协议登录。
- iCloud 登录态可能过期；过期后需要重新协议登录。
- 邮件同步依赖当前 iCloud Mail 服务地址和 Cookie。
