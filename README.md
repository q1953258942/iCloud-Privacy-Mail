# iCloud Privacy Mail 取码平台

独立项目，用来管理 iCloud 隐私邮箱 API 地址，并给注册项目提供取验证码接口。

当前版本是 MVP：

- 支持本地 Web 面板。
- 支持录入 iCloud 账号标签。
- 支持手动导入已经创建好的隐私邮箱。
- 支持为每个隐私邮箱生成独立 API 地址。
- 支持导入邮件测试数据。
- 支持从邮件标题/正文提取 6 位验证码。
- 预留 iCloud Provider 接口位置，后续接真实 Apple/iCloud 隐私邮箱创建能力。

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

`config.json`、`data/`、`logs/` 默认不会提交 Git。

## 使用流程

1. 先在外部 iCloud/隐私邮箱平台创建好邮箱。
2. 在本项目面板里添加 iCloud 账号标签。
3. 导入隐私邮箱，例如 `alias@icloud.com`。
4. 面板会生成 `API 地址`。
5. 注册项目使用这个 API 地址取验证码。

## 对外取码 API

按邮箱取码：

```http
GET /api/v1/mailboxes/{email}/code?key=<mailbox_key>&after=<RFC3339>
```

按邮箱 ID 取码：

```http
GET /api/mailboxes/{id}/code?key=<mailbox_key>&after=<RFC3339>
```

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

## 当前限制

当前版本还没有接真实 Apple/iCloud 自动创建隐私邮箱接口。创建邮箱前提是：

- 你已经在外部系统创建好了隐私邮箱。
- 或者后续把真实 iCloud Provider 接到本项目。

也就是说，本项目现在先把“邮箱 API 工作台”和“取码 API”跑通，后面再补“自动创建隐私邮箱”。

## 后续实现顺序

1. 接真实 iCloud Provider。
2. 自动创建 Hide My Email 地址。
3. 自动同步邮件。
4. 增加账号登录态状态：`need_login`、`need_2fa`、`no_icloud_plus`、`rate_limited`。
5. 给主注册项目新增 `icloud_api` 邮箱来源。

