# iCloud Privacy Mail 取码平台

独立 Go 服务，用来登录 iCloud、创建 Hide My Email 隐私邮箱、同步验证码邮件，并给外部注册项目提供取码 API。

当前版本是 **全协议后端**：不依赖比特浏览器、CDP、浏览器页面脚本或手动复制 Cookie。

## 功能总览

- 账号密码注册/登录：第一个注册账号自动成为管理员，后续账号为普通用户。
- 管理员数据管理：管理员可查看所有用户、iCloud 登录态和隐私邮箱；普通用户只能操作自己的数据。
- 旧接口登录态：后端发起 iCloud 登录，用户收到 2FA 后提交 6 位验证码保存登录态。
- 多 Apple 登录态：同一平台账号可保存多个 Apple/iCloud 登录态，前端按账号 TAB 分开显示和操作。
- 隐私邮箱创建：优先调用 Apple Account 新接口创建，账号只有旧登录态时回落 iCloud Hide My Email `generate + reserve`。
- 批量/定时创建：可勾选多个 Apple 登录态；手动创建会让选中账号同时跑一轮，定时只设置间隔，失败账号只在本次定时创建中临时跳过，其他账号继续创建，直到本次账号全部失败后等待下一次。
- 邮件同步：创建邮箱的 Apple 登录态只用于创建；验证码收件使用 iCloud 邮箱账号 + App 专用密码，通过 IMAP 监听和同步最新验证码邮件。
- 取码 API：每个隐私邮箱自动生成独立 `mailbox_key` 和 API 地址。
- 自动取号 API：外部项目可用全局 `api_key` 领取可用邮箱，领取后自动标记为已使用。
- 登录态检测：可手动检测 iCloud Mail 是否还能同步，也可在前端开启定时检测。
- 数据导出：当前登录用户可导出自己有权访问的数据；管理员导出全量数据；邮箱/API 导出支持按 Apple 登录态筛选。
- 瞬断重试：iCloud 登录后续步骤和 Hide My Email 列表同步遇到 EOF/timeout 等临时网络错误会短重试；2FA/OTP 校验不会重复提交。

## 目录结构

```text
cmd/panel/                 Go 服务入口
internal/app/              后端业务、协议客户端、状态存储和模板
internal/app/templates/    前端页面模板
config.example.json        配置模板
README.md                  使用与部署说明
更新日志.md                 公开版功能更新记录
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

## Apple Account 协议排障约定

新版 Apple Account 新接口登录/隐私邮箱创建协议，只以本机 Roxy 浏览器实操链路作为一手证据。

排查时必须使用用户指定的 Roxy 窗口，通过 CDP 重新打开目标页面、实际登录、提交 2FA，并记录本次请求顺序、method/path、状态码、关键响应头指纹和脱敏请求体。`C:\Users\Administrator\Desktop\*.har` 等用户历史抓包只能作为背景材料；除非用户明确要求，不得作为实现依据，不得用它覆盖 Roxy 实操结论。

涉及验证码/2FA 时，禁止同时触发多种发码方式；默认使用 `signin/complete` 自动下发的受信任设备验证码，不额外重发、不自动切短信。提交验证码时只按本次实际发码方式验证。

证据记录禁止保存或输出完整 Cookie、scnt、session、API key、密码、验证码。

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
| `update_enabled` | 是否启用面板“检测更新/在线更新”，默认 `true` |
| `update_repository` | 未配置 manifest 时读取的 GitHub 仓库，默认 `q1953258942/iCloud-Privacy-Mail` |
| `update_manifest_url` | 可选的更新 manifest 地址；配置后优先按 manifest 选择当前系统架构的二进制和 sha256 |
| `update_asset_name` | 可选的发布资产文件名；不填时自动匹配当前 `os/arch` |

示例：

```json
{
  "host": "127.0.0.1",
  "port": 8787,
  "data_path": "/opt/icloud-privacy-mail/shared/data/state.json",
  "api_key": "CHANGE_ME_GLOBAL_API_KEY",
  "public_base_url": "https://www.example.com",
  "icloud_default_host": "www.icloud.com.cn",
  "icloud_client_id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
  "update_enabled": true,
  "update_repository": "q1953258942/iCloud-Privacy-Mail",
  "update_manifest_url": "",
  "update_asset_name": ""
}
```

> 管理面板只支持账号密码登录；旧版 Admin Key 管理入口已移除。
>
> `data_path` 是唯一真实数据源，里面包含平台用户、Apple 登录态、隐私邮箱、邮件缓存和每个邮箱的 `mailbox_key`。部署、迁移或合并数据前必须先备份这个文件。

### 在线更新

面板顶部会显示当前版本；鼠标移到版本号上会显示最新版本号、发布时间和更新内容。管理员检测到新版本后可点击“更新”下载对应系统架构的二进制并替换当前程序，`data_path` 不会被覆盖。

在线更新默认读取 GitHub 最新 Release，并自动匹配文件名中包含当前 `GOOS/GOARCH` 的资产。如果仓库还没有发布 Release，面板会退回读取 GitHub 默认分支最新 commit：当前程序编译时写入的 commit 与默认分支一致时显示已是最新源码；默认分支已有新提交但没有 Release 资产时，只提示源码有更新，不显示一键更新按钮。更稳妥的公开发布方式是配置 `update_manifest_url`，manifest 格式如下：

```json
{
  "version": "2026.07.02",
  "name": "2026.07.02",
  "notes": "修复登录态保活显示，新增在线更新检测。",
  "published_at": "2026-07-02T00:00:00Z",
  "assets": [
    {
      "name": "panel_linux_amd64",
      "os": "linux",
      "arch": "amd64",
      "url": "https://github.com/q1953258942/iCloud-Privacy-Mail/releases/download/2026.07.02/panel_linux_amd64",
      "sha256": "..."
    }
  ]
}
```

Linux 服务器建议使用 systemd 托管并设置 `Restart=on-failure` 或 `Restart=always`。在线更新替换二进制后会用非 0 退出码结束当前进程，交给 systemd 自动拉起新版。Windows 运行中的 exe 不支持安全自替换，面板只提供检测，不执行在线替换。

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

### 1. 保存旧接口登录态

1. 进入 `/login` 注册或登录平台账号。
2. 进入首页，在 `保存 Apple 登录态` 输入 Apple ID 和密码。
3. 点击 `保存旧接口登录态`。
4. 如果 Apple 要求 2FA，在受信任设备允许后，把 6 位验证码填入面板。
5. 点击 `提交旧接口验证码`。
6. 后端会完成 `2sv/trust`、`accountLogin` 和 `setup/ws/1/validate`，并把 iCloud Cookie 写入服务器 `data_path`。

密码只参与当前登录请求，不写入状态文件、不返回前端、不写日志。

同一平台账号可以保存多个 Apple 登录态。保存成功后会生成一个内部 `account_id`，后续创建、同步、导出都会用这个 `account_id` 绑定数据；前端会用 TAB 展示不同 Apple 账号，避免多个账号的邮箱混在一起。

### 2. 保存新接口登录态

这是正式面板功能，不是 live 测试专用代码。它用于保存 Apple Account 新接口登录态，后续创建 Hide My Email 时走 `account/manage/email/private/*` 新接口。

1. 进入首页，在 `保存 Apple 登录态` 输入 Apple ID 和密码。
2. 点击 `保存新接口登录态`。
3. Apple 返回需要 2FA 时，默认等待受信任设备验证码；收到 6 位验证码后填入面板。
4. 点击 `提交新接口验证码`。
5. 后端会在 2FA 通过后尝试补一次 Apple 信任确认，并保存独立的新接口登录态，包含 `scnt`、管理接口 Cookie、动态 `apiKey` 等必要字段。

新接口和旧 iCloud Web 登录态分别保存在同一个 Apple 账号记录的 `login_states` 中：

- `icloud_web`：旧 Hide My Email/iCloud 邮件接口使用，每小时约 5 个创建额度。
- `apple_account`：Apple Account 管理接口使用，每小时约 20 个创建额度。

创建邮箱时，后端会优先使用 `apple_account` 新接口；如果账号只有旧 `icloud_web` 登录态，则仍可按旧接口创建。两种登录态互不覆盖，账号数据、邮箱归属和 API 地址仍沿用原来的保存方式。两种登录态都保存后可以一起创建：新接口每小时约 20 个，旧接口每小时约 5 个，合计约 25 个/小时。

新接口的 `account/manage` 管理态和浏览器里的 “Remember me” 不等同于旧 iCloud Web 的长效 Cookie。Apple Account 管理接口返回的是短期活动窗口，后端会按 Apple 返回的 TTL 到期时间刷新 `scnt`、Cookie 和 `apiKey`；刷新成功后才写回状态文件，非 2xx 失败响应不会覆盖已保存的 `scnt` 或 Cookie。旧接口之所以更长效，是因为它额外完成 `2sv/trust`、`accountLogin` 的 `extended_login` 交换，并保存 iCloud WebServices Cookie。

排障时可使用 `IPM_DEBUG_APPLE_ACCOUNT=1` 查看脱敏后的请求摘要。日志只输出 method/path、状态码、Cookie 长度和响应头指纹；响应体中的 API key、token、session、账号和邮箱字段会被脱敏，不输出完整 Cookie、`scnt`、密码或验证码。

### 3. 创建隐私邮箱

1. 登录态保存成功后，在 `创建隐私邮箱` 区域填写标签、备注，并勾选参与创建的 Apple 登录态。
2. 点击 `开始创建`；当前勾选账号会在同一次请求里同时各创建 1 个。
3. 后端优先调用 Apple Account 新接口创建邮箱；没有新接口登录态时回退旧 iCloud Hide My Email 接口。
4. 本次结果会记录成功数量和账号级失败；某个账号失败不会阻断其他账号。
5. 每个邮箱会生成独立 API 地址和 `mailbox_key`。

定时创建只保留间隔配置，默认间隔为 `60` 分钟。没有总数和每次轮数输入，面板旁边只记录累计成功/失败数量。每次定时开始后，当前勾选账号会同时创建；若某个账号在本次定时创建里达到上限或创建失败，只会临时跳过这个账号，其他账号继续创建；直到本次参与账号都临时失败后，任务才进入等待。下一次定时开始时会重新尝试全部勾选账号。

创建结果会绑定当前 Apple 登录态：

- `account_id`：内部账号 ID，用于数据归属和导出筛选。
- `account_apple_id`：前端展示用的 Apple ID。
- `account_label`：创建时填写的标签或 Apple ID。

如果从 iCloud 同步已有 Hide My Email 地址，后端会按当前登录态写入对应 `account_id`，不会再放到“未绑定 Apple 账号”分组。

### 4. 同步邮件和取验证码

- 面板可手动点击 `同步邮件`。
- 服务启动后会默认启用后台取码同步器；所有 `API active`、`iCloud active` 且已保存取码登录的邮箱会自动进入同步池，不需要先访问取码 API 才开始监听。
- 后台取码同步器会为每个取码登录态维持 IMAP `IDLE` 常驻连接；监听启动时先读取当前 `UIDNEXT` 作为账号级起跑线，之后 iCloud 收到新邮件并推送 `EXISTS` 事件后，后端只同步新 UID 并写入本地库。
- 同步时优先使用取码登录态里的账号级 `IMAPLastSyncUID` 做 `UID n:*` 增量抓取；兼容旧邮箱级 `LastSyncUID`，没有 UID 游标时才按日期回看兜底。
- IMAP 连接会优先使用 TCP 公共 DNS，并以 UDP DNS、本机 resolver 和 Apple IMAP IPv4 直连兜底，减少服务器 resolver 或 DNS 53 端口偶发超时导致验证码不能及时入库的问题；直连仍使用 `imap.mail.me.com` 做 TLS SNI。
- 后台同步默认 3 秒一轮作为兜底；最近被取码 API 访问过的邮箱会被排到本轮前面并立即唤醒同步器，避免 IMAP 事件漏掉或连接被 Apple 断开后长时间不入库。
- 对外取码 API 会先读取本地已同步邮件；未命中时触发后台快速补抓，普通请求默认最多等待 600ms，带 `wait_ms` 时最多可等待 30 秒，仍未命中就让调用方继续轮询。
- 后台同步器或快速补抓完成后都会写入本地状态，下一次取码轮询通常直接从本地返回验证码。
- 普通取码成功后会记录本次返回的邮件 ID；同一封验证码邮件不会被默认重复返回，避免重新发码后仍命中旧码。
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
| `wait_ms` | 可选；本地未命中时最多等待后台补抓多久，最大 30000；面板复制的 API 默认带 `12000` |
| `allow_stale` | 默认 false；只有排障时才建议打开，允许同步失败后回退本地缓存旧码 |
| `cache` | 默认 false；设为 `1/true` 时只读本地缓存，允许查看已返回过的旧验证码，不触发 iCloud 同步 |

取码提速相关配置：

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `mail_watcher_enabled` / `MAIL_WATCHER_ENABLED` | `true` | 是否启用后台取码同步器 |
| `mail_watcher_poll_ms` / `MAIL_WATCHER_POLL_MS` | `3000` | 后台取码同步器轮询间隔 |
| `mail_watcher_fetch_limit` / `MAIL_WATCHER_FETCH_LIMIT` | `8` | 后台同步每轮最多扫描最近多少个邮件线程 |
| `mail_watcher_initial_fetch_limit` / `MAIL_WATCHER_INITIAL_FETCH_LIMIT` | `20` | 兼容旧配置；实时取码监听启动后会先保存当前 UID 起跑线，不再预抓历史邮件 |
| `mail_watcher_lookback_hours` / `MAIL_WATCHER_LOOKBACK_HOURS` | `24` | 兼容旧配置；实时取码监听不再按时间回看旧邮件 |
| `public_fast_sync_wait_ms` / `PUBLIC_FAST_SYNC_WAIT_MS` | `600` | 取码 API 本地未命中后，最多等待后台快速同步多久 |
| `public_sync_min_interval_ms` / `PUBLIC_SYNC_MIN_INTERVAL_MS` | `3000` | 同一用户下 iCloud 邮件同步的最小间隔，避免前端高频轮询打满 Apple 接口 |

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
- 前端导出可选择 `当前 TAB 账号`、`全部登录态` 或指定 Apple 登录态。
- 普通用户只能导出自己的登录态和隐私邮箱；管理员可导出全量数据。
- 导出文件包含 iCloud Cookie 和邮箱 API token，属于敏感文件，不要发给无关人员。

### 邮箱 API token 稳定性

每个邮箱的 API token 存在 `data_path` 的 `mailboxes[].api_token` 字段里：

- 正常重启服务、重新构建程序、更新前端或重启服务器，不会改变已有邮箱的 API token。
- 修改 `public_base_url` 只会改变复制出来的 URL 前缀，不会改变 `key=` 后面的 token。
- 只有删除/重建邮箱记录、手动修改状态文件、从其他机器覆盖 `state.json`、或以后实现“重置 API token”功能时，token 才会改变。
- 如果部署时用本地 `state.json` 覆盖服务器旧数据，同邮箱的 `api_token` 可能被本地值覆盖，之前发出去的 API 地址会失效。

### 安全合并状态文件

跨机器迁移或把本地数据合并到服务器时，建议规则：

1. 先备份服务器当前 `state.json`。
2. 以邮箱地址 `email` 作为唯一匹配键。
3. 服务器已有的邮箱记录必须优先保留服务器侧 `api_token`。
4. 本地只更新标签、状态、归属账号、同步时间、邮件计数等元数据。
5. 只有服务器不存在的新邮箱，才写入本地 `api_token`。
6. 合并后检查文件权限，确保服务进程能读取。

如果 token 被误覆盖，可以从部署前备份里按邮箱地址找回旧 `api_token`，再写回当前 `state.json`。

### 导出接口参数

前端按钮最终调用：

```http
GET /api/runtime/export-mailbox-apis?format=txt&account_id=<account_id>
GET /api/runtime/export-mailbox-emails?format=txt&account_id=<account_id>
```

参数：

| 参数 | 说明 |
| --- | --- |
| `format` | `txt`、`csv`、`tsv`、`jsonl` |
| `account_id` | 可选；只导出指定 Apple 登录态创建/同步的邮箱 |
| `owner_id` | 仅管理员可用；在账号数据管理页按平台用户过滤 |

普通用户即使传入别人的 `owner_id` 也不会越权，后端仍按当前登录用户的数据范围导出。

## 服务器部署

推荐部署结构：

```text
/opt/icloud-privacy-mail/
  icloud-privacy-mail
  config.json
  shared/data/state.json
  backups/
```

`shared/data/state.json` 推荐只允许服务用户读写，例如：

```bash
chown -R icloud-mail:icloud-mail /opt/icloud-privacy-mail/shared
chmod 700 /opt/icloud-privacy-mail/shared/data
chmod 600 /opt/icloud-privacy-mail/shared/data/state.json
```

如果部署后页面空白、登录态丢失或日志出现 `permission denied`，优先检查 `state.json` 的属主和权限。

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
- 2FA pending 状态只保存在进程内；服务重启后需要重新保存登录态。
- iCloud 登录态可能过期；过期后需要重新保存登录态。
- 邮件同步依赖当前 iCloud Mail 服务地址和 Cookie。
