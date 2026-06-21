# iCloud Privacy Mail 取码平台接入设计

> 目标：把截图里的 iCloud Privacy Mail / 隐私邮箱 API 工作台接入当前 Go 面板，作为新的邮箱来源使用。注册、登录拿 CPA、登录设置 2FA/TOTP 的 OpenAI/Codex 协议流程不改，只替换“邮箱取号 + 轮询验证码”这一层。

## 1. 当前结论

当前项目已有三类取码来源：

1. `outlook`：本地 Outlook 账号池，格式 `邮箱----密码----clientId----refreshToken`。
2. `outlook/code_url`：取码链接，格式 `邮箱----验证码URL`。
3. `luckmail`：第三方邮箱平台自动取号、轮询验证码。

需要新增：

4. `icloud_api`：iCloud Privacy Mail API 取码平台。

推荐第一阶段只做 **接入外部 iCloud Privacy Mail API 地址**，不在当前项目里直接实现 Apple/iCloud 登录、隐私邮箱创建、会话维护和邮件同步。原因：

- 截图中的平台已经有 `API active`、`iCloud active`、`API 地址`、`验证码`、`邮件` 等完整能力。
- 当前项目只需要一个稳定取码接口，不需要关心对方平台内部如何管理 iCloud 账号。
- 这样改动最小，风险集中在新增邮箱来源，不影响现有注册协议。

## 2. 术语

| 名称 | 含义 |
| --- | --- |
| iCloud Privacy Mail | 隐私邮箱平台，用 iCloud 账号创建/管理 Hide My Email 地址，并对外提供取码 API |
| API active | 该隐私邮箱/API 通道已启用，可被外部项目调用 |
| iCloud active | 底层 iCloud 登录态、隐私邮箱权限、邮件读取能力正常 |
| API 地址 | 外部系统用来取验证码的 HTTP 地址 |
| 隐私邮箱 | iCloud Hide My Email 生成的邮箱别名 |
| 取码接口 | 当前项目调用的 HTTP API，返回 OpenAI 邮件里的 6 位 OTP |
| 素材行 | 用户导入到当前项目里的邮箱材料 |

## 3. 使用范围

本设计覆盖：

- 新增邮箱来源 `icloud_api`。
- 支持从 iCloud API 自动取号。
- 支持导入固定 iCloud API 邮箱行。
- 支持轮询 iCloud API 地址提取验证码。
- 支持注册、登录拿 CPA、登录设置 2FA/TOTP 共用该来源。
- 支持前端运行配置和邮箱平台配置。
- 支持日志脱敏、错误展示、状态保存。

本设计不覆盖第一阶段：

- 不直接实现 Apple ID 登录。
- 不直接实现 iCloud Hide My Email 创建。
- 不直接保存 Apple Cookie、iCloud Session、2FA 登录态。
- 不复制截图平台的完整后台管理系统。

如果后续要自建完整 iCloud Privacy Mail 平台，见本文第 15 节。

## 4. 用户侧格式

### 4.1 固定邮箱 + API 地址

新增导入格式：

```text
邮箱----iCloudAPI地址
```

示例：

```text
demo_alias@icloud.com----https://example.local/api/code?key=API_KEY&email=demo_alias%40icloud.com
```

用途：

- 当前项目使用 `demo_alias@icloud.com` 注册/登录。
- 触发 OpenAI 邮件验证码后，轮询后面的 API 地址取 OTP。

### 4.2 固定邮箱 + 标签 + API 地址

可选增强格式：

```text
邮箱----标签----iCloudAPI地址
```

示例：

```text
demo_alias@icloud.com----UPI-70-13----https://example.local/api/code?key=API_KEY&email=demo_alias%40icloud.com
```

用途：

- 面板里展示 `UPI-70-13`，方便和截图平台里的标签对应。

### 4.3 平台自动取号

当 `source=icloud_api` 且没有导入固定邮箱时，当前项目调用配置里的取号接口：

```http
POST /api/v1/mailboxes/claim
```

期望返回一个可用邮箱和取码 API 地址。

## 5. 配置设计

扩展 `email_platform_config.json`。

### 5.1 新增字段

```json
{
  "source": "icloud_api",
  "icloud_api_base_url": "http://127.0.0.1:8787",
  "icloud_api_key": "",
  "icloud_api_project": "openai",
  "icloud_api_timeout": 180,
  "icloud_api_interval": 3,
  "icloud_api_max_code_attempts": 15,
  "icloud_api_auto_claim": true,
  "icloud_api_specified_email": ""
}
```

字段说明：

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `source` | string | `outlook` | 新增支持 `icloud_api` |
| `icloud_api_base_url` | string | 空 | iCloud Privacy Mail 平台地址 |
| `icloud_api_key` | string | 空 | API Key，前端保存时可留空或保留星号表示沿用旧值 |
| `icloud_api_project` | string | `openai` | 项目标识，用于平台侧筛选邮件/模板 |
| `icloud_api_timeout` | int | `180` | 等待验证码总秒数 |
| `icloud_api_interval` | float | `3` | 轮询间隔秒 |
| `icloud_api_max_code_attempts` | int | `15` | 最多轮询次数 |
| `icloud_api_auto_claim` | bool | `true` | 是否允许从平台自动取号 |
| `icloud_api_specified_email` | string | 空 | 固定邮箱/邮箱列表，留空自动取号 |

### 5.2 前端展示

邮箱平台配置弹窗新增选项：

```text
邮箱来源：
- Outlook 账号池
- LuckMail API
- iCloud Privacy Mail API
```

当选择 `iCloud Privacy Mail API` 时展示：

- Base URL
- API Key
- 项目编码
- 超时秒
- 轮询间隔秒
- 验证码最多尝试
- 自动取号开关
- 指定邮箱/指定 API 地址

### 5.3 脱敏规则

以下字段不允许在前端明文回显：

- `icloud_api_key`
- 完整 `icloud_api_code_url`
- Cookie、Session、Token、Apple 登录态

前端只显示：

```text
已配置：********abcd
```

日志只显示：

```text
[iCloudAPI] 等待验证码：demo_alias@icloud.com api=[REDACTED]
```

## 6. 当前项目内部数据结构

当前 `用于注册的邮箱.json` 可以继续复用，新增字段即可。

建议每行结构：

```json
{
  "id": 1,
  "email": "demo_alias@icloud.com",
  "status": "available",
  "email_source": "icloud_api",
  "code_source": "iCloud API",
  "icloud_label": "UPI-70-13",
  "icloud_api_url": "https://example.local/api/code?key=***&email=demo_alias%40icloud.com",
  "note": "",
  "created_at": "2026-06-21T12:00:00+08:00",
  "used_at": ""
}
```

### 6.1 状态枚举

| 状态 | 中文 | 说明 |
| --- | --- | --- |
| `available` | 可用 | 可以被注册/登录任务领取 |
| `used` | 已使用 | 成功注册/登录后标记 |
| `failed` | 失败 | 明确失败，例如账号停用、取码接口无效 |
| `pending` | 等待中 | 批次已领取，流程还没结束 |
| `disabled` | 已停用 | 用户手动停用，不参与取号 |

面板状态下拉继续支持自定义改状态：可用、已使用、失败、停用。

## 7. 外部 iCloud API 契约

第一阶段支持两种接口形态：

1. 标准接口：当前项目按固定路径调用。
2. 兼容接口：用户直接粘贴截图平台复制出来的完整 `API 地址`。

### 7.1 健康检查

```http
GET /api/v1/health
Authorization: Bearer <api_key>
```

成功：

```json
{
  "success": true,
  "service": "icloud-privacy-mail",
  "api_active": true,
  "icloud_active": true,
  "time": "2026-06-21T12:00:00+08:00"
}
```

失败：

```json
{
  "success": false,
  "code": "icloud_inactive",
  "message": "iCloud 登录态失效",
  "retryable": false
}
```

### 7.2 自动取号

```http
POST /api/v1/mailboxes/claim
Authorization: Bearer <api_key>
Content-Type: application/json
```

请求：

```json
{
  "project": "openai",
  "purpose": "register",
  "count": 1
}
```

成功：

```json
{
  "success": true,
  "mailbox": {
    "email": "demo_alias@icloud.com",
    "label": "UPI-70-13",
    "api_url": "https://example.local/api/v1/mailboxes/demo_alias%40icloud.com/code",
    "api_active": true,
    "icloud_active": true
  }
}
```

无可用邮箱：

```json
{
  "success": false,
  "code": "no_available_mailbox",
  "message": "没有可用隐私邮箱",
  "retryable": false
}
```

### 7.3 轮询验证码

```http
GET /api/v1/mailboxes/{email}/code?project=openai&after=2026-06-21T12%3A00%3A00%2B08%3A00
Authorization: Bearer <api_key>
```

参数：

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `project` | 否 | 项目标识，默认 `openai` |
| `after` | 是 | 触发 OTP 之后的时间，只接受这个时间之后的新邮件 |
| `keyword` | 否 | 邮件关键词，默认 `OpenAI` |

成功：

```json
{
  "success": true,
  "email": "demo_alias@icloud.com",
  "code": "123456",
  "subject": "Your OpenAI code is 123456",
  "received_at": "2026-06-21T12:00:15+08:00",
  "message_id": "msg_xxx"
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

底层 iCloud 失效：

```json
{
  "success": false,
  "code": "icloud_inactive",
  "message": "iCloud 登录态失效",
  "retryable": false
}
```

API 停用：

```json
{
  "success": false,
  "code": "api_disabled",
  "message": "API 已停用",
  "retryable": false
}
```

### 7.4 完整 API 地址兼容

如果素材行直接给完整 URL：

```text
demo_alias@icloud.com----https://example.local/show/code?id=abc
```

当前项目直接 `GET` 该 URL，支持从以下响应提取验证码：

1. JSON：

```json
{"code":"123456"}
```

```json
{"success":true,"data":{"otp":"123456"}}
```

2. HTML：

```html
Your OpenAI code is 123456
```

3. 纯文本：

```text
验证码：123456
```

提取规则沿用当前 OTP 正则：

```text
6 位数字，优先匹配 OpenAI/code/验证码/OTP 附近文本
```

## 8. 当前项目内部接口改动

### 8.1 读取配置

现有：

```http
GET /api/email-platform/config
```

需要新增返回字段：

```json
{
  "config": {
    "source": "icloud_api",
    "icloud_api_base_url": "http://127.0.0.1:8787",
    "icloud_api_key_masked": "********abcd",
    "icloud_api_key_configured": true,
    "icloud_api_project": "openai",
    "icloud_api_timeout": 180,
    "icloud_api_interval": 3,
    "icloud_api_max_code_attempts": 15,
    "icloud_api_auto_claim": true,
    "icloud_api_specified_email": ""
  }
}
```

### 8.2 保存配置

现有：

```http
POST /api/email-platform/config
```

保存规则：

- `icloud_api_key` 为空：保留旧 key。
- `icloud_api_key` 是星号掩码：保留旧 key。
- `icloud_api_key` 是新值：覆盖保存。
- Base URL 去掉尾部 `/`。
- 超时范围：`15-1800` 秒。
- 轮询间隔：`1-60` 秒。
- 最大尝试：`1-200` 次。

### 8.3 导入邮箱素材

现有：

```http
POST /api/outlook/import
```

继续复用这个接口，但解析时支持：

```text
邮箱----iCloudAPI地址
邮箱----标签----iCloudAPI地址
```

识别规则：

- 第二段或第三段是 `http://` / `https://` URL。
- 邮箱域是 `icloud.com`、`me.com`、`privaterelay.appleid.com` 或用户自定义允许域。
- 保存为 `email_source=icloud_api`。

## 9. 注册/登录流程接入点

### 9.1 取号

伪流程：

```text
claimEmailAccount()
  if source == outlook:
      从账号池领取
  if source == luckmail:
      调 LuckMail 取号
  if source == icloud_api:
      优先指定邮箱
      再从本地 icloud_api 素材池领取
      如果开启 auto_claim，则调用外部平台取号
```

### 9.2 等待验证码

伪流程：

```text
waitForEmailOTP(email, triggerTime)
  if account.CodeURL != "":
      走现有取码链接逻辑
  if account.EmailSource == "icloud_api":
      走 iCloud API 轮询逻辑
  if account.EmailSource == "outlook":
      走 Graph/REST/IMAP
  if source == luckmail:
      走 LuckMail 轮询
```

### 9.3 新鲜度

必须传入触发 OTP 后的时间 `triggerTime`。

取码时只接受：

- `received_at >= triggerTime - 允许偏移`
- 默认允许偏移 10 秒，避免平台时间误差。

目的：

- 防止拿到旧验证码。
- 避免出现 `Wrong code`。

## 10. 错误码映射

| 外部 code/现象 | 当前项目处理 | 是否重试 |
| --- | --- | --- |
| `no_code` | 继续等待 | 是 |
| HTTP 408/429/500/502/503/504 | 记录警告，继续等待或换代理重试 | 是 |
| `api_disabled` | 当前邮箱失败 | 否 |
| `icloud_inactive` | 当前邮箱失败，提示 iCloud 登录态失效 | 否 |
| `mailbox_not_found` | 当前邮箱失败 | 否 |
| `invalid_api_key` | 批次失败，提示 API Key 错误 | 否 |
| `no_available_mailbox` | 批次失败或换下一个本地邮箱 | 否 |
| 响应里没有验证码 | 继续等待 | 是 |
| 返回旧验证码 | 忽略，继续等待 | 是 |

日志示例：

```text
[INFO] [iCloudAPI] 等待验证码：demo_alias@icloud.com attempt=1
[WARN] [iCloudAPI] 暂未收到验证码：demo_alias@icloud.com
[INFO] [iCloudAPI] 提取 OTP=[REDACTED_OTP] email=demo_alias@icloud.com
```

## 11. 前端改动点

### 11.1 统计卡片

`邮箱来源` 显示：

```text
iCloud API
```

### 11.2 邮箱平台配置弹窗

新增 iCloud API 配置区域：

```text
Base URL
API Key
项目编码
超时秒
轮询间隔秒
验证码最多尝试
自动取号
指定邮箱/API 地址
```

选择不同来源时，只显示对应配置块：

- Outlook：隐藏 LuckMail/iCloud 字段。
- LuckMail：显示 LuckMail 字段。
- iCloud API：显示 iCloud 字段。

### 11.3 邮箱素材表格

`取码方式` 显示：

```text
iCloud API
```

状态仍可手动修改：

- 可用
- 已使用
- 失败
- 停用

备注显示：

```text
标签：UPI-70-13
```

### 11.4 日志按钮

现有：

- 刷新日志
- 复制日志
- 清空日志
- 暂停批次

无需新增，只要 iCloud API 日志走同一批次日志。

## 12. Go 代码改动清单

预计改动文件：

| 文件 | 改动 |
| --- | --- |
| `internal/gopanel/server.go` | 增加 `emailSourceICloudAPI`、配置字段、保存/读取配置、导入解析 |
| `internal/gopanel/protocol_email.go` | 增加 iCloud API 取码 fetcher 或统一取码入口 |
| `internal/gopanel/go_batch.go` | 取号时识别 `icloud_api` |
| `internal/gopanel/go_storage.go` | 保存成功账号时保留 iCloud API 来源、标签、取码链接 |
| `templates/dashboard.html` | 邮箱平台配置 UI、状态显示、导入提示 |
| `templates/viewer.html` | 成功账号里显示来源和复制整行时保留取码信息 |
| `README.md` | 补充 iCloud API 使用说明 |
| `email_platform_config.example.json` | 补充示例字段 |
| `internal/gopanel/server_test.go` | 增加配置、导入解析、取码提取测试 |

## 13. Go 实现结构建议

### 13.1 配置结构

```go
type EmailPlatformConfig struct {
    Source string `json:"source"`

    LuckMailAPIKey string `json:"luckmail_api_key"`
    // existing LuckMail fields...

    ICloudAPIBaseURL         string  `json:"icloud_api_base_url"`
    ICloudAPIKey             string  `json:"icloud_api_key"`
    ICloudAPIProject         string  `json:"icloud_api_project"`
    ICloudAPITimeout         int     `json:"icloud_api_timeout"`
    ICloudAPIInterval        float64 `json:"icloud_api_interval"`
    ICloudAPIMaxCodeAttempts int     `json:"icloud_api_max_code_attempts"`
    ICloudAPIAutoClaim       bool    `json:"icloud_api_auto_claim"`
    ICloudAPISpecifiedEmail  string  `json:"icloud_api_specified_email"`
}
```

### 13.2 Fetcher 接口

```go
type emailOTPFetcher interface {
    WaitOTP(ctx context.Context, account *claimedEmail, after time.Time, logger *batchLogger) (string, error)
}
```

实现：

```text
outlookFetcher
luckmailFetcher
codeURLFetcher
icloudAPIFetcher
```

### 13.3 iCloud API 请求

```go
type icloudAPIClient struct {
    baseURL string
    apiKey  string
    client  *http.Client
}
```

请求头：

```http
Authorization: Bearer <api_key>
Accept: application/json,text/html,text/plain
User-Agent: go-panel/icloud-api
```

禁止打印：

- Authorization
- 完整 URL query
- 完整响应里可能含邮件正文的敏感内容

## 14. 测试计划

### 14.1 单元测试

新增测试：

1. `source=icloud_api` 配置保存/读取。
2. 掩码 key 保存时不覆盖原 key。
3. 导入 `邮箱----iCloudAPI地址`。
4. 导入 `邮箱----标签----iCloudAPI地址`。
5. JSON 响应提取 `code`。
6. JSON 响应提取 `data.otp`。
7. HTML 响应提取 6 位验证码。
8. `no_code` 不报失败，继续轮询。
9. `icloud_inactive` 直接失败。
10. 旧验证码被忽略。

### 14.2 集成测试

用 `httptest.Server` 模拟 iCloud API：

```text
第一次返回 no_code
第二次返回 no_code
第三次返回 code=123456
```

期望：

- 日志中前两次是等待。
- 第三次提取 OTP。
- 不泄露 API Key。

### 14.3 手工验证

1. 启动面板。
2. 打开 `邮箱平台配置`。
3. 选择 `iCloud Privacy Mail API`。
4. 填 Base URL、API Key、项目编码。
5. 导入一行 `邮箱----API地址`。
6. 点击 `开始注册`。
7. 日志出现：

```text
[iCloudAPI] 等待验证码
[iCloudAPI] 提取 OTP=[REDACTED_OTP]
```

8. 成功账号列表显示邮箱来源 `icloud_api`。

## 15. 后续：自建完整 iCloud Privacy Mail 平台

如果后面要实现截图里的完整系统，需要单独做一个服务，不建议直接塞进当前注册面板。

### 15.1 核心模块

| 模块 | 说明 |
| --- | --- |
| iCloud 账号管理 | 保存账号、登录态状态、标签、启停 |
| 隐私邮箱创建队列 | 批量创建 Hide My Email 地址 |
| 隐私邮箱列表 | 标签、API 状态、iCloud 状态、收件数 |
| 邮件工作台 | 查看邮件、搜索、提取验证码 |
| API 管理 | 创建/停用/删除 API 地址 |
| 取码网关 | 对外提供取码接口 |
| 同步任务 | 定时同步邮件、刷新状态 |
| 审计日志 | 记录 API 调用、失败原因、状态变更 |

### 15.2 表结构草案

```sql
CREATE TABLE icloud_accounts (
  id INTEGER PRIMARY KEY,
  label TEXT,
  apple_id TEXT NOT NULL,
  status TEXT NOT NULL,
  icloud_status TEXT NOT NULL,
  session_ref TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE privacy_mailboxes (
  id INTEGER PRIMARY KEY,
  icloud_account_id INTEGER NOT NULL,
  label TEXT,
  email TEXT NOT NULL UNIQUE,
  api_key_hash TEXT NOT NULL,
  api_active INTEGER NOT NULL DEFAULT 1,
  icloud_active INTEGER NOT NULL DEFAULT 1,
  receive_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE mail_messages (
  id INTEGER PRIMARY KEY,
  mailbox_id INTEGER NOT NULL,
  external_message_id TEXT,
  subject TEXT,
  sender TEXT,
  body_text TEXT,
  received_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
```

### 15.3 自建平台 API

```http
GET /api/v1/mailboxes
POST /api/v1/mailboxes
POST /api/v1/mailboxes/{id}/verify
GET /api/v1/mailboxes/{id}/messages
GET /api/v1/mailboxes/{id}/code
POST /api/v1/mailboxes/{id}/disable
DELETE /api/v1/mailboxes/{id}
```

### 15.4 自建平台前提

底层 iCloud 账号必须满足：

- iCloud+ 或具备 Hide My Email / 隐私邮箱能力。
- Apple ID 2FA 可用。
- iCloud 邮件转发/收件能力正常。
- 登录态能稳定刷新。
- 账号没有被风控、锁定、停用。

状态建议：

| 状态 | 含义 |
| --- | --- |
| `active` | 正常 |
| `need_login` | 需要重新登录 |
| `need_2fa` | 需要 2FA |
| `no_icloud_plus` | 没有隐私邮箱权限 |
| `rate_limited` | 被限速 |
| `disabled` | 已停用 |
| `failed` | 失败 |

## 16. 实现顺序

建议按这个顺序做，避免一次改太多：

1. 增加配置字段和前端表单。
2. 增加 `source=icloud_api` 识别。
3. 增加导入格式 `邮箱----API地址`。
4. 增加 iCloud API 轮询取码 fetcher。
5. 接入注册流程。
6. 接入登录 CPA、登录 TOTP 流程。
7. 增加状态显示、手动改状态。
8. 增加测试。
9. 更新 README。
10. 打包前脱敏检查。

## 17. 验收标准

必须满足：

- Outlook 原流程不受影响。
- LuckMail 原流程不受影响。
- `邮箱----验证码URL` 原流程不受影响。
- 新增 `邮箱----iCloudAPI地址` 可以注册成功。
- 新增 `source=icloud_api` 可以自动取号。
- 等待验证码最多尝试次数生效。
- 暂停批次时可以中断 iCloud API 轮询。
- 日志不泄露 API Key、完整 URL、Cookie、Token。
- 失败邮箱在邮箱池里能显示邮箱和失败原因。
- 成功账号复制整行时保留邮箱、TOTP、取码来源和 Token。

## 18. 打包注意

交付包不能包含：

- `email_platform_config.json` 里的真实 API Key。
- `proxy_config.json` 里的真实代理。
- `register_config.json` 里的个人配置。
- 真实邮箱池。
- 成功 Token。
- CPA JSON。
- 批次日志里的敏感内容。

交付包应该包含：

- `go-panel.exe`
- `sentinel/`
- `templates/`
- `README.md`
- `交付包使用说明.md`
- `email_platform_config.example.json`
- `proxy_config.example.json`
- `register_config.example.json`
- 本设计文档

