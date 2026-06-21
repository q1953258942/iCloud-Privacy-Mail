package app

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed templates/index.html
var webFS embed.FS

type Server struct {
	cfg                  Config
	store                *FileStore
	logger               *slog.Logger
	mux                  *http.ServeMux
	icloudProtocolLogins *appleAuthPendingStore
}

func NewServer(cfg Config, store *FileStore, logger *slog.Logger) http.Handler {
	s := &Server{
		cfg:                  cfg,
		store:                store,
		logger:               logger,
		mux:                  http.NewServeMux(),
		icloudProtocolLogins: newAppleAuthPendingStore(),
	}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.requiresAdmin(r) && !s.authorizedAdmin(r) {
		writeError(w, http.StatusUnauthorized, errCode("admin_auth_required", "管理接口需要 Admin Key", false))
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /", s.handleHome)
	s.mux.HandleFunc("GET /api/status", s.handleStatus)
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("POST /api/v1/mailboxes/claim", s.handleClaimMailbox)
	s.mux.HandleFunc("GET /api/icloud/session", s.handleICloudSession)
	s.mux.HandleFunc("POST /api/icloud/protocol-login/start", s.handleStartICloudProtocolLogin)
	s.mux.HandleFunc("POST /api/icloud/protocol-login/2fa", s.handleSubmitICloudProtocol2FA)
	s.mux.HandleFunc("POST /api/icloud/browser/open", s.handleOpenICloudBrowser)
	s.mux.HandleFunc("POST /api/icloud/session/save", s.handleSaveICloudSession)
	s.mux.HandleFunc("POST /api/icloud/session/check", s.handleCheckICloudSession)
	s.mux.HandleFunc("POST /api/icloud/mailboxes/create", s.handleCreateICloudMailbox)
	s.mux.HandleFunc("GET /api/accounts", s.handleListAccounts)
	s.mux.HandleFunc("POST /api/accounts", s.handleCreateAccount)
	s.mux.HandleFunc("GET /api/mailboxes", s.handleListMailboxes)
	s.mux.HandleFunc("POST /api/mailboxes", s.handleCreateMailbox)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/verify", s.handleVerifyMailbox)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/disable", s.handleDisableMailbox)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/status", s.handleSetMailboxStatus)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/sync", s.handleSyncMailbox)
	s.mux.HandleFunc("DELETE /api/mailboxes/{id}", s.handleDeleteMailbox)
	s.mux.HandleFunc("GET /api/mailboxes/{id}/messages", s.handleListMessages)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/messages", s.handleCreateMessage)
	s.mux.HandleFunc("GET /api/mailboxes/{id}/code", s.handleMailboxCodeByID)
	s.mux.HandleFunc("GET /api/v1/mailboxes/{email}/code", s.handleMailboxCodeByEmail)
}

func (s *Server) handleHome(w http.ResponseWriter, _ *http.Request) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, errCode("template_missing", "面板模板缺失", false))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	state := s.store.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"success":            true,
		"service":            "icloud-privacy-mail",
		"api_key_configured": strings.TrimSpace(s.cfg.APIKey) != "",
		"admin_key_required": strings.TrimSpace(s.cfg.AdminKey) != "",
		"base_url":           requestBaseURL(r),
		"accounts":           len(state.Accounts),
		"mailboxes":          len(state.Mailboxes),
		"messages":           len(state.Messages),
		"icloud_session":     publicSession(state.ICloudSession),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.cfg.APIKey) != "" && !s.authorizedGlobalAPI(r) {
		writeError(w, http.StatusUnauthorized, errCode("invalid_api_key", "API Key 错误", false))
		return
	}
	session, ok := s.store.ICloudSession()
	icloudActive := ok && session.IsICloudPlus && session.CanCreateHME && len(session.Cookies) > 0
	writeJSON(w, http.StatusOK, map[string]any{
		"success":       true,
		"service":       "icloud-privacy-mail",
		"api_active":    strings.TrimSpace(s.cfg.APIKey) != "",
		"icloud_active": icloudActive,
		"time":          formatTime(time.Now()),
	})
}

func (s *Server) handleClaimMailbox(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedGlobalAPI(r) {
		writeError(w, http.StatusUnauthorized, errCode("global_api_key_required", "自动取号需要配置并提交全局 API Key", false))
		return
	}
	var payload struct {
		Project string `json:"project"`
		Purpose string `json:"purpose"`
		Count   int    `json:"count"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		_ = r.Body.Close()
	}
	note := strings.TrimSpace(payload.Project)
	if strings.TrimSpace(payload.Purpose) != "" {
		note = strings.TrimSpace(note + " " + payload.Purpose)
	}
	if note == "" {
		note = "外部 API 已领取"
	} else {
		note = "外部 API 已领取：" + note
	}
	mailbox, err := s.store.ClaimAvailableMailbox(note)
	if err != nil {
		writeError(w, http.StatusOK, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"mailbox": s.publicMailbox(r, mailbox),
	})
}

func (s *Server) handleICloudSession(w http.ResponseWriter, _ *http.Request) {
	session, ok := s.store.ICloudSession()
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "session": publicSession(nil)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "session": publicSession(&session)})
}

func (s *Server) handleCheckICloudSession(w http.ResponseWriter, r *http.Request) {
	session, ok := s.store.ICloudSession()
	if !ok {
		writeError(w, http.StatusBadRequest, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录或手动保存登录态", true))
		return
	}

	checkedAt := time.Now()
	if err := NewICloudClient().CheckMailSession(r.Context(), session); err != nil {
		session.LastCheckedAt = checkedAt
		session.LastCheckOK = false
		session.LastStatusMessage = "最近检测失败：" + formatTime(checkedAt) + "；iCloud Mail 不可用，请重新协议登录/保存登录态"
		if saveErr := s.store.SaveICloudSession(session); saveErr != nil {
			writeError(w, http.StatusInternalServerError, saveErr)
			return
		}
		s.logger.Warn("iCloud session check failed", "err", err)
		writeError(w, http.StatusBadGateway, errCode("icloud_session_check_failed", session.LastStatusMessage, true))
		return
	}

	session.LastCheckedAt = checkedAt
	session.LastCheckOK = true
	session.LastStatusMessage = "最近检测正常：" + formatTime(checkedAt) + "；iCloud Mail 可同步"
	if err := s.store.SaveICloudSession(session); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":    true,
		"checked_at": formatTime(checkedAt),
		"message":    session.LastStatusMessage,
		"session":    publicSession(&session),
	})
}

func (s *Server) handleStartICloudProtocolLogin(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AppleID  string `json:"apple_id"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := NewAppleAuthClient().StartLogin(
		r.Context(),
		payload.AppleID,
		payload.Password,
		s.cfg.ICloudDefaultHost,
		s.cfg.ICloudClientID,
		s.icloudProtocolLogins,
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if result.Needs2FA {
		writeJSON(w, http.StatusOK, map[string]any{
			"success":    true,
			"needs_2fa":  true,
			"pending_id": result.PendingID,
			"apple_id":   result.AppleID,
			"expires_at": formatTime(result.ExpiresAt),
			"message":    result.Message,
		})
		return
	}
	if err := s.store.SaveICloudSession(result.Session); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"needs_2fa": false,
		"message":   result.Message,
		"session":   publicSession(&result.Session),
	})
}

func (s *Server) handleSubmitICloudProtocol2FA(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		PendingID string `json:"pending_id"`
		Code      string `json:"code"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	pending, ok := s.icloudProtocolLogins.get(payload.PendingID)
	if !ok {
		writeError(w, http.StatusBadRequest, errCode("apple_login_pending_expired", "协议登录已过期，请重新输入账号密码发起登录", true))
		return
	}
	session, err := NewAppleAuthClient().Submit2FA(r.Context(), pending, payload.Code)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.icloudProtocolLogins.delete(payload.PendingID)
	if err := s.store.SaveICloudSession(session); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "Apple 协议 2FA 登录成功，登录态已保存",
		"session": publicSession(&session),
	})
}

func (s *Server) handleOpenICloudBrowser(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		BrowserID string `json:"browser_id"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	browserID := firstNonEmpty(payload.BrowserID, s.cfg.BitBrowserID)
	result, err := NewBitBrowserClient(s.cfg.BitBrowserAPI).OpenOrCreate(r.Context(), browserID, s.cfg.ICloudLoginURL)
	if err != nil {
		writeError(w, http.StatusBadGateway, errCode("bitbrowser_open_failed", err.Error(), true))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":    true,
		"browser_id": result.BrowserID,
		"cdp_http":   result.HTTP,
		"login_url":  s.cfg.ICloudLoginURL,
		"message":    "已打开浏览器，请手动登录 iCloud 后点击保存登录态",
	})
}

func (s *Server) handleSaveICloudSession(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		CDPHTTP   string `json:"cdp_http"`
		BrowserID string `json:"browser_id"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	cdpHTTP := strings.TrimSpace(payload.CDPHTTP)
	if cdpHTTP == "" {
		browserID := firstNonEmpty(payload.BrowserID, s.cfg.BitBrowserID)
		if browserID == "" {
			writeError(w, http.StatusBadRequest, errCode("missing_cdp_http", "缺少 CDP HTTP 地址；请先点击打开登录窗口或手动填写 127.0.0.1:端口", true))
			return
		}
		result, err := NewBitBrowserClient(s.cfg.BitBrowserAPI).OpenOrCreate(r.Context(), browserID, s.cfg.ICloudLoginURL)
		if err != nil {
			writeError(w, http.StatusBadGateway, errCode("bitbrowser_open_failed", err.Error(), true))
			return
		}
		cdpHTTP = result.HTTP
	}
	session, err := NewCDPSessionClient().SaveICloudSession(r.Context(), cdpHTTP, s.cfg.ICloudDefaultHost)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if err := s.store.SaveICloudSession(session); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"session": publicSession(&session),
	})
}

func (s *Server) handleCreateICloudMailbox(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID string `json:"account_id"`
		Label     string `json:"label"`
		Note      string `json:"note"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	session, ok := s.store.ICloudSession()
	if !ok {
		writeError(w, http.StatusBadRequest, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先手动登录并保存登录态", true))
		return
	}
	remote, err := NewICloudClient().CreatePrivacyMailbox(r.Context(), session, payload.Label, payload.Note)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	note := strings.TrimSpace(remote.Note)
	if note == "" {
		note = "created by iCloud protocol"
	}
	mailbox, err := s.store.AddMailbox(payload.AccountID, remote.Label, remote.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if note != "" {
		updated, updateErr := s.store.SetMailboxStatus(mailbox.ID, nil, nil, StatusAvailable, note)
		if updateErr == nil {
			mailbox = updated
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"remote": map[string]any{
			"anonymous_id": remote.AnonymousID,
			"email":        remote.Email,
			"is_active":    remote.IsActive,
		},
		"mailbox": s.publicMailbox(r, mailbox),
	})
}

func (s *Server) handleListAccounts(w http.ResponseWriter, _ *http.Request) {
	state := s.store.Snapshot()
	out := make([]publicAccount, 0, len(state.Accounts))
	for _, account := range state.Accounts {
		out = append(out, publicAccount{
			ID:           account.ID,
			Label:        account.Label,
			AppleID:      maskAppleID(account.AppleID),
			Status:       account.Status,
			ICloudStatus: account.ICloudStatus,
			Note:         account.Note,
			CreatedAt:    formatTime(account.CreatedAt),
			UpdatedAt:    formatTime(account.UpdatedAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "accounts": out})
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Label   string `json:"label"`
		AppleID string `json:"apple_id"`
		Note    string `json:"note"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	account, err := s.store.AddAccount(payload.Label, payload.AppleID, payload.Note)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "account": account})
}

func (s *Server) handleListMailboxes(w http.ResponseWriter, r *http.Request) {
	state := s.store.Snapshot()
	out := make([]publicMailbox, 0, len(state.Mailboxes))
	for _, mailbox := range state.Mailboxes {
		out = append(out, s.publicMailbox(r, mailbox))
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "mailboxes": out})
}

func (s *Server) handleCreateMailbox(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID string `json:"account_id"`
		Label     string `json:"label"`
		Email     string `json:"email"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	mailbox, err := s.store.AddMailbox(payload.AccountID, payload.Label, payload.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "mailbox": s.publicMailbox(r, mailbox)})
}

func (s *Server) handleVerifyMailbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	active := true
	mailbox, err := s.store.SetMailboxStatus(id, &active, &active, StatusAvailable, "手动验证通过")
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "mailbox": s.publicMailbox(r, mailbox)})
}

func (s *Server) handleDisableMailbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	inactive := false
	mailbox, err := s.store.SetMailboxStatus(id, &inactive, nil, StatusDisabled, "API 已停用")
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "mailbox": s.publicMailbox(r, mailbox)})
}

func (s *Server) handleSetMailboxStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var payload struct {
		Status       string `json:"status"`
		Note         string `json:"note"`
		APIActive    *bool  `json:"api_active"`
		ICloudActive *bool  `json:"icloud_active"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	status := strings.ToLower(strings.TrimSpace(payload.Status))
	if status != "" && !validMailboxStatus(status) {
		writeError(w, http.StatusBadRequest, errCode("invalid_status", "状态只能是 available、used、failed、active、disabled", false))
		return
	}
	mailbox, err := s.store.SetMailboxStatus(id, payload.APIActive, payload.ICloudActive, status, payload.Note)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "mailbox": s.publicMailbox(r, mailbox)})
}

func (s *Server) handleSyncMailbox(w http.ResponseWriter, r *http.Request) {
	mailbox, ok := s.store.FindMailboxByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	after, err := parseAfter(r.URL.Query().Get("after"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	count, err := s.syncMailbox(r.Context(), mailbox, after, strings.TrimSpace(r.URL.Query().Get("keyword")))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "synced": count})
}

func (s *Server) handleDeleteMailbox(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteMailbox(r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.store.FindMailboxByID(id); !ok {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	messages := s.store.MessagesForMailbox(id)
	out := make([]publicMessage, 0, len(messages))
	for _, msg := range messages {
		out = append(out, publicMessage{
			ID:         msg.ID,
			MailboxID:  msg.MailboxID,
			Subject:    msg.Subject,
			From:       msg.From,
			Body:       msg.Body,
			ReceivedAt: formatTime(msg.ReceivedAt),
			CreatedAt:  formatTime(msg.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "messages": out})
}

func (s *Server) handleCreateMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var payload struct {
		Subject    string `json:"subject"`
		From       string `json:"from"`
		Body       string `json:"body"`
		ReceivedAt string `json:"received_at"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	receivedAt := time.Now()
	if strings.TrimSpace(payload.ReceivedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, payload.ReceivedAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, errCode("invalid_received_at", "received_at 必须是 RFC3339 时间", false))
			return
		}
		receivedAt = parsed
	}
	msg, err := s.store.AddMessage(id, payload.Subject, payload.From, payload.Body, receivedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "message": msg})
}

func (s *Server) handleMailboxCodeByID(w http.ResponseWriter, r *http.Request) {
	mailbox, ok := s.store.FindMailboxByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	s.writeMailboxCode(w, r, mailbox)
}

func (s *Server) handleMailboxCodeByEmail(w http.ResponseWriter, r *http.Request) {
	email, err := url.PathUnescape(r.PathValue("email"))
	if err != nil {
		writeError(w, http.StatusBadRequest, errCode("invalid_email", "邮箱路径非法", false))
		return
	}
	mailbox, ok := s.store.FindMailboxByEmail(email)
	if !ok {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	s.writeMailboxCode(w, r, mailbox)
}

func (s *Server) writeMailboxCode(w http.ResponseWriter, r *http.Request, mailbox Mailbox) {
	if !s.authorized(r, mailbox) {
		writeError(w, http.StatusUnauthorized, errCode("invalid_api_key", "API Key 错误", false))
		return
	}
	if !mailbox.APIActive || mailbox.Status == StatusDisabled {
		writeError(w, http.StatusForbidden, errCode("api_disabled", "API 已停用", false))
		return
	}
	if !mailbox.ICloudActive {
		writeError(w, http.StatusForbidden, errCode("icloud_inactive", "iCloud 登录态失效", false))
		return
	}
	after, err := parseAfter(r.URL.Query().Get("after"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	keyword := strings.TrimSpace(r.URL.Query().Get("keyword"))
	if keyword == "" {
		keyword = "OpenAI"
	}
	allowStale := truthy(r.URL.Query().Get("allow_stale"))
	var syncErr error
	if _, err := s.syncMailbox(r.Context(), mailbox, after, keyword); err != nil {
		syncErr = err
		s.logger.Warn("icloud sync failed", "mailbox_id", mailbox.ID, "err", err)
	}

	canUseLocalCache := syncErr == nil || allowStale || !after.IsZero()
	if canUseLocalCache {
		msg, code, ok := latestMailboxCode(s.store.MessagesForMailbox(mailbox.ID), after, keyword)
		if !ok && syncErr != nil && allowStale && !after.IsZero() {
			msg, code, ok = latestMailboxCode(s.store.MessagesForMailbox(mailbox.ID), time.Time{}, keyword)
		}
		if ok {
			payload := map[string]any{
				"success":     true,
				"email":       mailbox.Email,
				"code":        code,
				"subject":     msg.Subject,
				"received_at": formatTime(msg.ReceivedAt),
				"message_id":  msg.ID,
			}
			if syncErr != nil {
				payload["stale_cache"] = true
				payload["sync_error"] = "iCloud 同步失败，当前验证码来自本地缓存"
			}
			writeJSON(w, http.StatusOK, payload)
			return
		}
	}
	if syncErr != nil && !allowStale {
		writeError(w, http.StatusBadGateway, errCode("icloud_sync_failed", "同步 iCloud 邮件失败，已拒绝返回本地旧验证码；请重新登录 iCloud 或稍后重试", true))
		return
	}
	writeError(w, http.StatusOK, errCode("no_code", "暂未收到验证码", true))
}

func latestMailboxCode(messages []Message, after time.Time, keyword string) (Message, string, bool) {
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		keyword = "OpenAI"
	}
	sort.SliceStable(messages, func(i, j int) bool {
		left := firstNonZeroTime(messages[i].ReceivedAt, messages[i].CreatedAt)
		right := firstNonZeroTime(messages[j].ReceivedAt, messages[j].CreatedAt)
		return left.After(right)
	})
	for _, msg := range messages {
		msgTime := firstNonZeroTime(msg.ReceivedAt, msg.CreatedAt)
		if !after.IsZero() && msgTime.Before(after.Add(-10*time.Second)) {
			continue
		}
		text := msg.Subject + "\n" + msg.Body
		if !strings.Contains(strings.ToLower(text), strings.ToLower(keyword)) && keyword != "OpenAI" {
			continue
		}
		code := extractOTP(text)
		if code == "" {
			continue
		}
		return msg, code, true
	}
	return Message{}, "", false
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func (s *Server) syncMailbox(ctx context.Context, mailbox Mailbox, after time.Time, keyword string) (int, error) {
	session, ok := s.store.ICloudSession()
	if !ok {
		return 0, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先手动登录并保存登录态", true)
	}
	messages, err := NewICloudClient().SyncMailboxMessages(ctx, session, mailbox, after, keyword, 50)
	if err != nil {
		return 0, err
	}
	synced := 0
	for _, msg := range messages {
		if extractOTP(msg.Subject+"\n"+msg.Body) == "" {
			continue
		}
		_, created, err := s.store.UpsertMessage(mailbox.ID, msg.RemoteID, "icloud", msg.Subject, msg.From, msg.Body, msg.ReceivedAt)
		if err != nil {
			return synced, err
		}
		if created {
			synced++
		}
	}
	return synced, nil
}

func (s *Server) authorized(r *http.Request, mailbox Mailbox) bool {
	candidates := []string{
		strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		r.Header.Get("X-API-Key"),
		r.URL.Query().Get("key"),
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if constantTimeEqual(candidate, mailbox.APIToken) {
			return true
		}
		if strings.TrimSpace(s.cfg.APIKey) != "" && constantTimeEqual(candidate, s.cfg.APIKey) {
			return true
		}
	}
	return false
}

func (s *Server) authorizedGlobalAPI(r *http.Request) bool {
	want := strings.TrimSpace(s.cfg.APIKey)
	if want == "" {
		return false
	}
	candidates := []string{
		strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		r.Header.Get("X-API-Key"),
		r.URL.Query().Get("key"),
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if constantTimeEqual(candidate, want) {
			return true
		}
	}
	return false
}

func (s *Server) requiresAdmin(r *http.Request) bool {
	if strings.TrimSpace(s.cfg.AdminKey) == "" {
		return false
	}
	if r.URL.Path == "/" {
		return false
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/v1/health" {
		return false
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/mailboxes/claim" {
		return false
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/mailboxes/") && strings.HasSuffix(r.URL.Path, "/code") {
		return false
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/mailboxes/") && strings.HasSuffix(r.URL.Path, "/code") {
		return false
	}
	return strings.HasPrefix(r.URL.Path, "/api/")
}

func (s *Server) authorizedAdmin(r *http.Request) bool {
	want := strings.TrimSpace(s.cfg.AdminKey)
	if want == "" {
		return true
	}
	candidates := []string{
		strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		r.Header.Get("X-Admin-Key"),
		r.URL.Query().Get("admin_key"),
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if constantTimeEqual(candidate, want) {
			return true
		}
	}
	return false
}

func constantTimeEqual(candidate, want string) bool {
	candidate = strings.TrimSpace(candidate)
	want = strings.TrimSpace(want)
	if candidate == "" || want == "" || len(candidate) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(want)) == 1
}

func (s *Server) publicMailbox(r *http.Request, mailbox Mailbox) publicMailbox {
	baseURL := firstNonEmpty(s.cfg.PublicBaseURL, requestBaseURL(r))
	apiURL := fmt.Sprintf("%s/api/v1/mailboxes/%s/code?key=%s", strings.TrimRight(baseURL, "/"), url.PathEscape(mailbox.Email), url.QueryEscape(mailbox.APIToken))
	return publicMailbox{
		ID:           mailbox.ID,
		AccountID:    mailbox.AccountID,
		Label:        mailbox.Label,
		Email:        mailbox.Email,
		APITokenMask: maskSecret(mailbox.APIToken, 6),
		APIURL:       apiURL,
		APIActive:    mailbox.APIActive,
		ICloudActive: mailbox.ICloudActive,
		ReceiveCount: mailbox.ReceiveCount,
		Status:       mailbox.Status,
		Note:         mailbox.Note,
		CreatedAt:    formatTime(mailbox.CreatedAt),
		UpdatedAt:    formatTime(mailbox.UpdatedAt),
	}
}

func publicSession(session *ICloudSession) publicICloudSession {
	if session == nil {
		return publicICloudSession{
			Saved:              false,
			NeedsManualLogin:   true,
			LastStatusMessage:  "未保存 iCloud 登录态",
			ProviderConfigured: false,
		}
	}
	message := strings.TrimSpace(session.LastStatusMessage)
	if message == "" {
		message = "登录态已保存；Cookie 原文只写入本地 data/state.json，不会返回前端"
	}
	return publicICloudSession{
		Saved:              true,
		SavedAt:            formatTime(session.SavedAt),
		AppleID:            maskAppleID(session.AppleID),
		DSIDMask:           maskSecret(session.DSID, 4),
		ClientBuildNumber:  session.ClientBuildNumber,
		MasteringNumber:    session.MasteringNumber,
		PremiumMailBaseURL: session.PremiumMailBaseURL,
		MailGatewayBaseURL: session.MailGatewayBaseURL,
		MailBaseURL:        session.MailBaseURL,
		Host:               session.Host,
		IsICloudPlus:       session.IsICloudPlus,
		CanCreateHME:       session.CanCreateHME,
		CookieCount:        len(session.Cookies),
		ProviderConfigured: session.IsICloudPlus && session.CanCreateHME && len(session.Cookies) > 0,
		NeedsManualLogin:   len(session.Cookies) == 0,
		LastCheckedAt:      formatTime(session.LastCheckedAt),
		LastCheckOK:        session.LastCheckOK,
		LastStatusMessage:  message,
	}
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, 1<<20)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errCode("bad_json", "JSON 请求体非法："+err.Error(), false)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	var coded codedError
	if errors.As(err, &coded) {
		writeJSON(w, status, apiError{
			Success:   false,
			Code:      coded.code,
			Message:   coded.message,
			Retryable: coded.retryable,
		})
		return
	}
	writeJSON(w, status, apiError{
		Success: false,
		Code:    "internal_error",
		Message: err.Error(),
	})
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func parseAfter(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errCode("invalid_after", "after 必须是 RFC3339 时间", false)
	}
	return parsed, nil
}

var (
	contextOTPRegex = regexp.MustCompile(`(?i)(?:openai|chatgpt|otp|code|verification|验证码|验证|代码)[^\d]{0,80}(\d{6})`)
	plainOTPRegex   = regexp.MustCompile(`\b(\d{6})\b`)
)

func extractOTP(text string) string {
	if matches := contextOTPRegex.FindStringSubmatch(text); len(matches) == 2 && validOTP(matches[1]) {
		return matches[1]
	}
	for _, matches := range plainOTPRegex.FindAllStringSubmatch(text, -1) {
		if len(matches) == 2 && validOTP(matches[1]) {
			return matches[1]
		}
	}
	return ""
}

func validOTP(code string) bool {
	return len(code) == 6 && code != "000000"
}

func validMailboxStatus(status string) bool {
	switch status {
	case StatusActive, StatusAvailable, StatusUsed, StatusFailed, StatusDisabled:
		return true
	default:
		return false
	}
}

func maskAppleID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	at := strings.Index(value, "@")
	if at <= 1 {
		return maskSecret(value, 4)
	}
	return value[:1] + "***" + value[at:]
}
