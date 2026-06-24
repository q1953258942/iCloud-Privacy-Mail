package app

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/csv"
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
	"sync"
	"time"
)

//go:embed templates/*.html
var webFS embed.FS

const mailboxCodeFreshWindow = 5 * time.Minute
const mailboxCreateMinInterval = 3 * time.Second
const mailboxCreateLimitCooldown = 2 * time.Minute

var mailboxMailSyncMinInterval = 3 * time.Second
var mailboxCodePollDebounce = 500 * time.Millisecond
var mailboxCodeBatchSyncTimeout = 120 * time.Second

type Server struct {
	cfg                   Config
	store                 *FileStore
	logger                *slog.Logger
	mux                   *http.ServeMux
	icloudProtocolLogins  *appleAuthPendingStore
	icloudCreateMu        sync.Mutex
	icloudCreateLast      map[string]time.Time
	icloudCreateCooldown  map[string]time.Time
	icloudMailSyncMu      sync.Mutex
	icloudMailSyncGates   map[string]chan struct{}
	icloudMailSyncLast    map[string]time.Time
	mailboxCodeMu         sync.Mutex
	mailboxCodePollers    map[string]*mailboxCodePoller
	schedulerMu           sync.Mutex
	mailboxSchedulers     map[string]*mailboxSchedulerJob
	createMailboxForOwner func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error)
	syncMailboxMessages   func(ctx context.Context, session ICloudSession, mailbox Mailbox, after time.Time, keyword string, maxThreads int) ([]ICloudSyncedMessage, error)
	syncMailboxBatch      func(ctx context.Context, session ICloudSession, mailboxes []Mailbox, after time.Time, keyword string, maxThreads int) (map[string][]ICloudSyncedMessage, error)
}

type createMailboxFailure struct {
	AccountID string `json:"account_id,omitempty"`
	AppleID   string `json:"apple_id,omitempty"`
	Error     string `json:"error"`
}

type syncICloudMailboxResult struct {
	AccountID string `json:"account_id,omitempty"`
	AppleID   string `json:"apple_id,omitempty"`
	Total     int    `json:"total"`
	Created   int    `json:"created"`
	Updated   int    `json:"updated"`
	Skipped   int    `json:"skipped"`
	Error     string `json:"error,omitempty"`
}

type mailboxCodeWaiter struct {
	ctx       context.Context
	mailboxID string
	after     time.Time
	keyword   string
	result    chan mailboxCodeResult
}

type mailboxCodeResult struct {
	message Message
	code    string
	ok      bool
	syncErr error
}

type mailboxCodePoller struct {
	ownerID string
	waiters []*mailboxCodeWaiter
}

func NewServer(cfg Config, store *FileStore, logger *slog.Logger) http.Handler {
	s := &Server{
		cfg:                  cfg,
		store:                store,
		logger:               logger,
		mux:                  http.NewServeMux(),
		icloudProtocolLogins: newAppleAuthPendingStore(),
		icloudCreateLast:     make(map[string]time.Time),
		icloudCreateCooldown: make(map[string]time.Time),
		icloudMailSyncGates:  make(map[string]chan struct{}),
		icloudMailSyncLast:   make(map[string]time.Time),
		mailboxCodePollers:   make(map[string]*mailboxCodePoller),
		mailboxSchedulers:    make(map[string]*mailboxSchedulerJob),
	}
	s.createMailboxForOwner = s.createICloudMailboxForOwner
	s.syncMailboxMessages = func(ctx context.Context, session ICloudSession, mailbox Mailbox, after time.Time, keyword string, maxThreads int) ([]ICloudSyncedMessage, error) {
		return NewICloudClient().SyncMailboxMessages(ctx, session, mailbox, after, keyword, maxThreads)
	}
	s.syncMailboxBatch = func(ctx context.Context, session ICloudSession, mailboxes []Mailbox, after time.Time, keyword string, maxThreads int) (map[string][]ICloudSyncedMessage, error) {
		return NewICloudClient().SyncMailboxMessagesBatch(ctx, session, mailboxes, after, keyword, maxThreads)
	}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.requiresAdmin(r) &&
		!s.authorizedAdminSession(r) &&
		!(s.allowsUserSession(r) && s.authorizedUserSession(r)) {
		writeError(w, http.StatusUnauthorized, errCode("auth_required", "请先登录账号", false))
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /", s.handleHome)
	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("GET /manage", s.handleManagePage)
	s.mux.HandleFunc("GET /api/auth/me", s.handleAuthMe)
	s.mux.HandleFunc("POST /api/auth/register", s.handleAuthRegister)
	s.mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)
	s.mux.HandleFunc("GET /api/status", s.handleStatus)
	s.mux.HandleFunc("GET /api/manage/data", s.handleManageData)
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("POST /api/v1/mailboxes/claim", s.handleClaimMailbox)
	s.mux.HandleFunc("GET /api/runtime/export", s.handleExportRuntimeData)
	s.mux.HandleFunc("GET /api/runtime/export-mailbox-apis", s.handleExportMailboxAPIs)
	s.mux.HandleFunc("GET /api/runtime/export-mailbox-emails", s.handleExportMailboxEmails)
	s.mux.HandleFunc("GET /api/icloud/session", s.handleICloudSession)
	s.mux.HandleFunc("POST /api/icloud/protocol-login/start", s.handleStartICloudProtocolLogin)
	s.mux.HandleFunc("POST /api/icloud/protocol-login/2fa", s.handleSubmitICloudProtocol2FA)
	s.mux.HandleFunc("POST /api/icloud/session/check", s.handleCheckICloudSession)
	s.mux.HandleFunc("POST /api/icloud/mailboxes/create", s.handleCreateICloudMailbox)
	s.mux.HandleFunc("POST /api/icloud/mailboxes/sync", s.handleSyncICloudMailboxes)
	s.mux.HandleFunc("GET /api/icloud/scheduler/status", s.handleMailboxSchedulerStatus)
	s.mux.HandleFunc("POST /api/icloud/scheduler/start", s.handleStartMailboxScheduler)
	s.mux.HandleFunc("POST /api/icloud/scheduler/stop", s.handleStopMailboxScheduler)
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
	s.writeTemplate(w, "templates/index.html")
}

func (s *Server) handleLoginPage(w http.ResponseWriter, _ *http.Request) {
	s.writeTemplate(w, "templates/login.html")
}

func (s *Server) handleManagePage(w http.ResponseWriter, _ *http.Request) {
	s.writeTemplate(w, "templates/manage.html")
}

func (s *Server) writeTemplate(w http.ResponseWriter, name string) {
	data, err := webFS.ReadFile(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errCode("template_missing", "面板模板缺失", false))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handleAuthRegister(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, err := s.store.CreateUser(payload.Username, payload.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	token, session, err := s.store.CreateWebSession(user.ID, user.IsAdmin, 30*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.setSessionCookie(w, r, token, session.ExpiresAt)
	writeJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"user":    publicUserFromUser(user),
		"message": firstNonEmpty(map[bool]string{true: "注册成功，当前账号是管理员", false: "注册成功"}[user.IsAdmin]),
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, err := s.store.AuthenticateUser(payload.Username, payload.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	token, session, err := s.store.CreateWebSession(user.ID, user.IsAdmin, 30*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.setSessionCookie(w, r, token, session.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"user":    publicUserFromUser(user),
	})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if session, user, ok := s.currentWebSession(r); ok {
		out := publicUserFromUser(user)
		out.IsAdmin = session.IsAdmin || user.IsAdmin
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "authenticated": true, "user": out})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "authenticated": false})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_ = s.store.DeleteWebSession(cookie.Value)
	}
	s.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	state := s.scopedState(r)
	currentUser := publicUser{}
	authenticated := false
	if session, user, ok := s.currentWebSession(r); ok {
		authenticated = true
		currentUser = publicUserFromUser(user)
		currentUser.IsAdmin = session.IsAdmin || user.IsAdmin
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":            true,
		"service":            "icloud-privacy-mail",
		"api_key_configured": strings.TrimSpace(s.cfg.APIKey) != "",
		"base_url":           requestBaseURL(r),
		"account_scoped":     scopedOwnerID(r, s.store) != "",
		"authenticated":      authenticated,
		"current_user":       currentUser,
		"accounts":           len(state.Accounts),
		"mailboxes":          len(state.Mailboxes),
		"messages":           len(state.Messages),
		"icloud_session":     s.publicSessionForRequest(r),
		"icloud_sessions":    s.publicSessionsForRequest(r),
	})
}

func (s *Server) handleManageData(w http.ResponseWriter, r *http.Request) {
	state := s.scopedState(r)
	users := state.Users
	if s.isAdminRequest(r) {
		users = s.store.Users()
	}
	publicUsers := make([]publicUser, 0, len(users))
	for _, user := range users {
		publicUsers = append(publicUsers, publicUserFromUser(user))
	}
	accounts := make([]publicAccount, 0, len(state.Accounts))
	for _, account := range state.Accounts {
		accounts = append(accounts, s.publicAccount(account))
	}
	mailboxes := make([]publicMailbox, 0, len(state.Mailboxes))
	for _, mailbox := range state.Mailboxes {
		mailboxes = append(mailboxes, s.publicMailbox(r, mailbox))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":         true,
		"is_admin":        s.isAdminRequest(r),
		"users":           publicUsers,
		"user_summaries":  s.publicUserSummaries(users, state),
		"accounts":        accounts,
		"mailboxes":       mailboxes,
		"messages":        len(state.Messages),
		"icloud_session":  s.publicSessionForRequest(r),
		"icloud_sessions": s.publicSessionsForRequest(r),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.cfg.APIKey) != "" && !s.authorizedGlobalAPI(r) {
		writeError(w, http.StatusUnauthorized, errCode("invalid_api_key", "API Key 错误", false))
		return
	}
	session, ok := s.store.ICloudSession()
	icloudActive := ok && session.IsICloudPlus && session.CanCreateHME && len(session.Cookies) > 0
	if !icloudActive {
		for _, scopedSession := range s.store.Snapshot().ICloudSessions {
			if scopedSession.IsICloudPlus && scopedSession.CanCreateHME && len(scopedSession.Cookies) > 0 {
				icloudActive = true
				break
			}
		}
	}
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

func (s *Server) handleExportRuntimeData(w http.ResponseWriter, r *http.Request) {
	ownerID := scopedOwnerID(r, s.store)
	state := s.scopedState(r)
	payload := struct {
		ExportedAt      string          `json:"exported_at"`
		Scope           string          `json:"scope"`
		Owner           string          `json:"owner,omitempty"`
		DataPath        string          `json:"data_path,omitempty"`
		NextID          int             `json:"next_id"`
		Accounts        []Account       `json:"accounts"`
		Mailboxes       []Mailbox       `json:"mailboxes"`
		ICloudSession   *ICloudSession  `json:"icloud_session,omitempty"`
		ICloudSessions  []ICloudSession `json:"icloud_sessions,omitempty"`
		MessageCount    int             `json:"message_count"`
		Messages        []Message       `json:"messages,omitempty"`
		IncludeMessages bool            `json:"include_messages"`
	}{
		ExportedAt:      formatTime(time.Now()),
		Scope:           "all",
		NextID:          state.NextID,
		Accounts:        state.Accounts,
		Mailboxes:       state.Mailboxes,
		ICloudSession:   state.ICloudSession,
		ICloudSessions:  state.ICloudSessions,
		MessageCount:    len(state.Messages),
		IncludeMessages: truthy(r.URL.Query().Get("include_messages")),
	}
	if ownerID != "" {
		payload.Scope = "user"
		payload.Owner = s.ownerName(ownerID)
	} else {
		payload.DataPath = s.store.Path()
	}
	if payload.IncludeMessages {
		payload.Messages = state.Messages
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	filename := "icloud-privacy-mail-state-" + time.Now().Format("20060102-150405") + ".json"
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(data, '\n'))
}

func (s *Server) handleExportMailboxAPIs(w http.ResponseWriter, r *http.Request) {
	s.writeMailboxTextExport(w, r, mailboxExportAPI)
}

func (s *Server) handleExportMailboxEmails(w http.ResponseWriter, r *http.Request) {
	s.writeMailboxTextExport(w, r, mailboxExportEmail)
}

type mailboxExportMode string

const (
	mailboxExportAPI   mailboxExportMode = "api"
	mailboxExportEmail mailboxExportMode = "email"
)

type mailboxExportFormat struct {
	ext         string
	contentType string
	separator   string
	csv         bool
	jsonl       bool
}

func (s *Server) writeMailboxTextExport(w http.ResponseWriter, r *http.Request, mode mailboxExportMode) {
	format, err := parseMailboxExportFormat(r.URL.Query().Get("format"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	state := s.scopedState(r)
	var out strings.Builder
	if format.jsonl {
		for _, mailbox := range state.Mailboxes {
			record := s.mailboxExportRecord(r, mailbox, mode)
			if len(record) == 0 {
				continue
			}
			var line any
			if mode == mailboxExportEmail {
				line = map[string]string{"email": record[0]}
			} else {
				line = map[string]string{"email": record[0], "api": record[1]}
			}
			data, err := json.Marshal(line)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			out.Write(data)
			out.WriteByte('\n')
		}
	} else if format.csv {
		writer := csv.NewWriter(&out)
		if format.separator == "\t" {
			writer.Comma = '\t'
		}
		for _, mailbox := range state.Mailboxes {
			record := s.mailboxExportRecord(r, mailbox, mode)
			if len(record) == 0 {
				continue
			}
			if err := writer.Write(record); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	} else {
		for _, mailbox := range state.Mailboxes {
			record := s.mailboxExportRecord(r, mailbox, mode)
			if len(record) == 0 {
				continue
			}
			out.WriteString(strings.Join(record, format.separator))
			out.WriteByte('\n')
		}
	}

	prefix := "icloud-mailbox-apis"
	if mode == mailboxExportEmail {
		prefix = "icloud-mailbox-emails"
	}
	filename := prefix + "-" + time.Now().Format("20060102-150405") + "." + format.ext
	w.Header().Set("Content-Type", format.contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, out.String())
}

func (s *Server) mailboxExportRecord(r *http.Request, mailbox Mailbox, mode mailboxExportMode) []string {
	email := strings.TrimSpace(mailbox.Email)
	if email == "" {
		return nil
	}
	if mode == mailboxExportEmail {
		return []string{email}
	}
	return []string{email, s.mailboxAPIURL(r, mailbox)}
}

func parseMailboxExportFormat(value string) (mailboxExportFormat, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "txt", "text", "list":
		return mailboxExportFormat{ext: "txt", contentType: "text/plain; charset=utf-8", separator: "----"}, nil
	case "csv":
		return mailboxExportFormat{ext: "csv", contentType: "text/csv; charset=utf-8", separator: ",", csv: true}, nil
	case "tsv", "tab":
		return mailboxExportFormat{ext: "tsv", contentType: "text/tab-separated-values; charset=utf-8", separator: "\t", csv: true}, nil
	case "jsonl", "ndjson":
		return mailboxExportFormat{ext: "jsonl", contentType: "application/x-ndjson; charset=utf-8", jsonl: true}, nil
	default:
		return mailboxExportFormat{}, errCode("invalid_export_format", "导出格式只支持 txt、csv、tsv、jsonl", false)
	}
}

func (s *Server) handleICloudSession(w http.ResponseWriter, r *http.Request) {
	sessions := s.publicSessionsForRequest(r)
	session := publicSession(nil)
	if len(sessions) > 0 {
		session = sessions[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "session": session, "sessions": sessions})
}

func (s *Server) handleCheckICloudSession(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID string `json:"account_id"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		_ = r.Body.Close()
	}
	ownerID := requestOwnerID(r, s.store)
	sessions := s.sessionsForOwner(ownerID, payload.AccountID)
	if len(sessions) == 0 {
		writeError(w, http.StatusBadRequest, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true))
		return
	}

	checkedAt := time.Now()
	client := NewICloudClient()
	failed := 0
	var lastErr error
	for _, session := range sessions {
		err := client.CheckMailSession(r.Context(), session)
		session.LastCheckedAt = checkedAt
		session.LastCheckOK = err == nil
		if err != nil {
			failed++
			lastErr = err
			session.LastStatusMessage = "最近检测失败：" + formatTime(checkedAt) + "；iCloud Mail 不可用，请重新协议登录"
		} else {
			session.LastStatusMessage = "最近检测正常：" + formatTime(checkedAt) + "；iCloud Mail 可同步"
		}
		if saveErr := s.store.SaveICloudSessionForOwner(ownerID, session); saveErr != nil {
			writeError(w, http.StatusInternalServerError, saveErr)
			return
		}
		if err != nil {
			s.logger.Warn("iCloud session check failed", "account_id", session.AccountID, "err", err)
		}
	}
	publicSessions := s.publicSessionsForOwner(ownerID)
	first := publicSession(nil)
	if len(publicSessions) > 0 {
		first = publicSessions[0]
	}
	if failed == len(sessions) {
		message := "全部 iCloud 登录态检测失败"
		if lastErr != nil {
			message += "：" + lastErr.Error()
		}
		s.logger.Warn("iCloud session check failed", "err", lastErr)
		writeError(w, http.StatusBadGateway, errCode("icloud_session_check_failed", message, true))
		return
	}
	message := "登录态检测正常"
	if failed > 0 {
		message = fmt.Sprintf("登录态部分检测成功：成功 %d，失败 %d", len(sessions)-failed, failed)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":       true,
		"checked_at":    formatTime(checkedAt),
		"message":       message,
		"session":       first,
		"sessions":      publicSessions,
		"checked_count": len(sessions),
		"failed_count":  failed,
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
	if err := s.store.SaveICloudSessionForOwner(requestOwnerID(r, s.store), result.Session); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	sessions := s.publicSessionsForRequest(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"needs_2fa": false,
		"message":   result.Message,
		"session":   publicSessionForAppleID(sessions, result.Session.AppleID),
		"sessions":  sessions,
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
	if err := s.store.SaveICloudSessionForOwner(requestOwnerID(r, s.store), session); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	sessions := s.publicSessionsForRequest(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"message":  "Apple 协议 2FA 登录成功，登录态已保存",
		"session":  publicSessionForAppleID(sessions, session.AppleID),
		"sessions": sessions,
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
	if !s.canAccessAccountID(r, payload.AccountID) {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
		return
	}
	ownerID := requestOwnerID(r, s.store)
	mailboxes, remotes, failures, err := s.createMailboxesForOwner(r.Context(), ownerID, payload.AccountID, payload.Label, payload.Note)
	if err != nil && len(mailboxes) == 0 {
		s.logICloudCreateError(ownerID, err)
		writeError(w, http.StatusBadGateway, err)
		return
	}
	out := make([]publicMailbox, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		out = append(out, s.publicMailbox(r, mailbox))
	}
	status := http.StatusCreated
	if len(failures) > 0 {
		status = http.StatusMultiStatus
	}
	firstMailbox := publicMailbox{}
	if len(out) > 0 {
		firstMailbox = out[0]
	}
	remoteOut := make([]map[string]any, 0, len(remotes))
	for _, remote := range remotes {
		remoteOut = append(remoteOut, map[string]any{
			"anonymous_id": remote.AnonymousID,
			"email":        remote.Email,
			"is_active":    remote.IsActive,
		})
	}
	writeJSON(w, status, map[string]any{
		"success":   true,
		"remote":    firstMap(remoteOut),
		"remotes":   remoteOut,
		"mailbox":   firstMailbox,
		"mailboxes": out,
		"created":   len(out),
		"failures":  failures,
	})
}

func (s *Server) handleSyncICloudMailboxes(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID string `json:"account_id"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		_ = r.Body.Close()
	}
	if !s.canAccessAccountID(r, payload.AccountID) {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
		return
	}
	ownerID := requestOwnerID(r, s.store)
	sessions := s.sessionsForOwner(ownerID, payload.AccountID)
	if len(sessions) == 0 {
		writeError(w, http.StatusBadRequest, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true))
		return
	}

	created := 0
	updated := 0
	skipped := 0
	total := 0
	failed := 0
	out := make([]publicMailbox, 0)
	results := make([]syncICloudMailboxResult, 0, len(sessions))
	for _, session := range sessions {
		result, rows, err := s.syncICloudMailboxesForSession(r.Context(), r, ownerID, session)
		results = append(results, result)
		if err != nil {
			failed++
			s.logger.Warn("iCloud mailbox list failed", "account_id", session.AccountID, "err", err)
			continue
		}
		total += result.Total
		created += result.Created
		updated += result.Updated
		skipped += result.Skipped
		out = append(out, rows...)
	}
	if failed == len(sessions) {
		writeError(w, http.StatusBadGateway, errCode("icloud_sync_failed", "全部 iCloud 账号同步失败", true))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"total":     total,
		"created":   created,
		"updated":   updated,
		"skipped":   skipped,
		"failed":    failed,
		"results":   results,
		"mailboxes": out,
	})
}

func (s *Server) syncICloudMailboxesForSession(ctx context.Context, r *http.Request, ownerID string, session ICloudSession) (syncICloudMailboxResult, []publicMailbox, error) {
	result := syncICloudMailboxResult{
		AccountID: session.AccountID,
		AppleID:   maskAppleID(session.AppleID),
	}
	remotes, err := NewICloudClient().ListPrivacyMailboxes(ctx, session)
	if err != nil {
		result.Error = err.Error()
		return result, nil, err
	}
	result.Total = len(remotes)
	out := make([]publicMailbox, 0, len(remotes))
	accountID := strings.TrimSpace(session.AccountID)
	for _, remote := range remotes {
		mailbox, isCreated, err := s.store.UpsertMailboxFromRemote(ownerID, accountID, remote, "synced from iCloud HME list")
		if err != nil {
			var coded codedError
			if errors.As(err, &coded) && coded.code == "mailbox_exists_other_owner" {
				result.Skipped++
				continue
			}
			result.Error = err.Error()
			return result, out, err
		}
		if isCreated {
			result.Created++
		} else {
			result.Updated++
		}
		out = append(out, s.publicMailbox(r, mailbox))
	}
	return result, out, nil
}

func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	state := s.scopedState(r)
	out := make([]publicAccount, 0, len(state.Accounts))
	for _, account := range state.Accounts {
		out = append(out, s.publicAccount(account))
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
	account, err := s.store.AddAccountForOwner(requestOwnerID(r, s.store), payload.Label, payload.AppleID, payload.Note)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "account": account})
}

func (s *Server) handleListMailboxes(w http.ResponseWriter, r *http.Request) {
	state := s.scopedState(r)
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
	if !s.canAccessAccountID(r, payload.AccountID) {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
		return
	}
	mailbox, err := s.store.AddMailboxForOwner(requestOwnerID(r, s.store), payload.AccountID, payload.Label, payload.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "mailbox": s.publicMailbox(r, mailbox)})
}

func (s *Server) handleVerifyMailbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canAccessMailboxID(r, id) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
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
	if !s.canAccessMailboxID(r, id) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
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
	if !s.canAccessMailboxID(r, id) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
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
	if !s.canAccessMailbox(r, mailbox) {
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
	id := r.PathValue("id")
	if !s.canAccessMailboxID(r, id) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	if err := s.store.DeleteMailbox(id); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	mailbox, ok := s.store.FindMailboxByID(id)
	if !ok || !s.canAccessMailbox(r, mailbox) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	messages := s.store.MessagesForMailbox(id)
	out := make([]publicMessage, 0, len(messages))
	for _, msg := range messages {
		out = append(out, publicMessage{
			ID:         msg.ID,
			OwnerID:    msg.OwnerID,
			Owner:      s.ownerName(msg.OwnerID),
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
	if !s.canAccessMailboxID(r, id) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
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
	now := time.Now()
	codeAfter := mailboxCodeAfter(after, now)
	allowStale := truthy(r.URL.Query().Get("allow_stale"))
	if msg, code, ok := latestMailboxCode(s.store.MessagesForMailbox(mailbox.ID), codeAfter, keyword, now); ok {
		s.writeMailboxCodeSuccess(w, mailbox, msg, code, "")
		return
	}

	result := s.waitMailboxCode(r.Context(), mailbox, codeAfter, keyword)
	if result.syncErr != nil {
		s.logger.Warn("icloud sync failed", "mailbox_id", mailbox.ID, "err", result.syncErr)
	}
	if result.ok {
		s.writeMailboxCodeSuccess(w, mailbox, result.message, result.code, staleCacheMessage(result.syncErr))
		return
	}
	if result.syncErr != nil && allowStale {
		if msg, code, ok := latestMailboxCode(s.store.MessagesForMailbox(mailbox.ID), codeAfter, keyword, time.Now()); ok {
			s.writeMailboxCodeSuccess(w, mailbox, msg, code, "iCloud 同步失败，当前验证码来自本地缓存")
			return
		}
	}
	if result.syncErr != nil && !allowStale {
		writeError(w, http.StatusBadGateway, errCode("icloud_sync_failed", "同步 iCloud 邮件失败，已拒绝返回本地旧验证码；请重新登录 iCloud 或稍后重试", true))
		return
	}
	writeError(w, http.StatusOK, errCode("no_code", "暂未收到验证码", true))
}

func (s *Server) writeMailboxCodeSuccess(w http.ResponseWriter, mailbox Mailbox, msg Message, code string, staleMessage string) {
	payload := map[string]any{
		"success":     true,
		"email":       mailbox.Email,
		"code":        code,
		"subject":     msg.Subject,
		"received_at": formatTime(msg.ReceivedAt),
		"message_id":  msg.ID,
	}
	if staleMessage != "" {
		payload["stale_cache"] = true
		payload["sync_error"] = staleMessage
	}
	writeJSON(w, http.StatusOK, payload)
}

func staleCacheMessage(err error) string {
	if err == nil {
		return ""
	}
	return "iCloud 同步失败，当前验证码来自本地缓存"
}

func mailboxCodeAfter(after, now time.Time) time.Time {
	if now.IsZero() {
		now = time.Now()
	}
	cutoff := now.Add(-mailboxCodeFreshWindow)
	if after.After(cutoff) {
		return after
	}
	return cutoff
}

func latestMailboxCode(messages []Message, after time.Time, keyword string, now time.Time) (Message, string, bool) {
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		keyword = "OpenAI"
	}
	after = mailboxCodeAfter(after, now)
	sort.SliceStable(messages, func(i, j int) bool {
		left := firstNonZeroTime(messages[i].ReceivedAt, messages[i].CreatedAt)
		right := firstNonZeroTime(messages[j].ReceivedAt, messages[j].CreatedAt)
		return left.After(right)
	})
	for _, msg := range messages {
		msgTime := firstNonZeroTime(msg.ReceivedAt, msg.CreatedAt)
		if msgTime.IsZero() || msgTime.Before(after) {
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

func (s *Server) waitMailboxCode(ctx context.Context, mailbox Mailbox, after time.Time, keyword string) mailboxCodeResult {
	waiter := &mailboxCodeWaiter{
		ctx:       ctx,
		mailboxID: mailbox.ID,
		after:     after,
		keyword:   keyword,
		result:    make(chan mailboxCodeResult, 1),
	}
	ownerKey := mailboxSyncOwnerKey(mailbox.OwnerID)
	s.mailboxCodeMu.Lock()
	if s.mailboxCodePollers == nil {
		s.mailboxCodePollers = make(map[string]*mailboxCodePoller)
	}
	poller := s.mailboxCodePollers[ownerKey]
	if poller == nil {
		poller = &mailboxCodePoller{ownerID: mailbox.OwnerID}
		s.mailboxCodePollers[ownerKey] = poller
		go s.runMailboxCodePoller(ownerKey, poller)
	}
	poller.waiters = append(poller.waiters, waiter)
	s.mailboxCodeMu.Unlock()

	select {
	case result := <-waiter.result:
		return result
	case <-ctx.Done():
		return mailboxCodeResult{syncErr: ctx.Err()}
	}
}

func (s *Server) runMailboxCodePoller(ownerKey string, poller *mailboxCodePoller) {
	for {
		if debounce := mailboxCodePollDebounce; debounce > 0 {
			time.Sleep(debounce)
		}
		s.mailboxCodeMu.Lock()
		waiters := poller.waiters
		poller.waiters = nil
		if len(waiters) == 0 {
			delete(s.mailboxCodePollers, ownerKey)
			s.mailboxCodeMu.Unlock()
			return
		}
		s.mailboxCodeMu.Unlock()
		s.resolveMailboxCodeWaiters(poller.ownerID, waiters)
	}
}

func (s *Server) resolveMailboxCodeWaiters(ownerID string, waiters []*mailboxCodeWaiter) {
	active := activeMailboxCodeWaiters(waiters)
	if len(active) == 0 {
		return
	}
	pending := make([]*mailboxCodeWaiter, 0, len(active))
	for _, waiter := range active {
		msg, code, ok := s.latestMailboxCodeForWaiter(waiter)
		if ok {
			deliverMailboxCodeResult(waiter, mailboxCodeResult{message: msg, code: code, ok: true})
			continue
		}
		pending = append(pending, waiter)
	}
	if len(pending) == 0 {
		return
	}
	syncCtx := context.Background()
	if pending[0].ctx != nil {
		syncCtx = context.WithoutCancel(pending[0].ctx)
	}
	syncCtx, cancel := context.WithTimeout(syncCtx, mailboxCodeBatchSyncTimeout)
	defer cancel()
	syncErr := s.syncMailboxesForCodeWaiters(syncCtx, ownerID, pending)
	for _, waiter := range pending {
		if waiterCanceled(waiter) {
			continue
		}
		msg, code, ok := s.latestMailboxCodeForWaiter(waiter)
		deliverMailboxCodeResult(waiter, mailboxCodeResult{message: msg, code: code, ok: ok, syncErr: syncErr})
	}
}

func activeMailboxCodeWaiters(waiters []*mailboxCodeWaiter) []*mailboxCodeWaiter {
	active := make([]*mailboxCodeWaiter, 0, len(waiters))
	for _, waiter := range waiters {
		if waiter == nil || waiterCanceled(waiter) {
			continue
		}
		active = append(active, waiter)
	}
	return active
}

func waiterCanceled(waiter *mailboxCodeWaiter) bool {
	if waiter == nil || waiter.ctx == nil {
		return false
	}
	select {
	case <-waiter.ctx.Done():
		return true
	default:
		return false
	}
}

func deliverMailboxCodeResult(waiter *mailboxCodeWaiter, result mailboxCodeResult) {
	select {
	case waiter.result <- result:
	default:
	}
}

func (s *Server) latestMailboxCodeForWaiter(waiter *mailboxCodeWaiter) (Message, string, bool) {
	return latestMailboxCode(s.store.MessagesForMailbox(waiter.mailboxID), waiter.after, waiter.keyword, time.Now())
}

func (s *Server) syncMailboxesForCodeWaiters(ctx context.Context, ownerID string, waiters []*mailboxCodeWaiter) error {
	byID := make(map[string]Mailbox)
	var minAfter time.Time
	for _, waiter := range waiters {
		if waiterCanceled(waiter) {
			continue
		}
		if minAfter.IsZero() || waiter.after.Before(minAfter) {
			minAfter = waiter.after
		}
		if _, seen := byID[waiter.mailboxID]; seen {
			continue
		}
		mailbox, ok := s.store.FindMailboxByID(waiter.mailboxID)
		if !ok || !mailbox.APIActive || mailbox.Status == StatusDisabled || !mailbox.ICloudActive {
			continue
		}
		byID[waiter.mailboxID] = mailbox
	}
	if len(byID) == 0 {
		return nil
	}
	mailboxes := make([]Mailbox, 0, len(byID))
	for _, mailbox := range byID {
		mailboxes = append(mailboxes, mailbox)
	}
	sort.Slice(mailboxes, func(i, j int) bool {
		return mailboxes[i].Email < mailboxes[j].Email
	})
	return s.syncMailboxBatchForOwner(ctx, ownerID, mailboxes, minAfter, "OpenAI")
}

func (s *Server) syncMailbox(ctx context.Context, mailbox Mailbox, after time.Time, keyword string) (int, error) {
	release, err := s.acquireMailboxSyncSlot(ctx, mailbox.OwnerID)
	if err != nil {
		return 0, err
	}
	defer release()

	if latestMailbox, ok := s.store.FindMailboxByID(mailbox.ID); ok {
		mailbox = latestMailbox
	}
	if err := s.waitMailboxSyncInterval(ctx, mailbox.OwnerID); err != nil {
		return 0, err
	}
	defer s.markMailboxSyncFinished(mailbox.OwnerID)
	session, ok := s.sessionForMailbox(mailbox.OwnerID, mailbox.AccountID)
	if !ok {
		return 0, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
	}
	syncFn := s.syncMailboxMessages
	if syncFn == nil {
		syncFn = func(ctx context.Context, session ICloudSession, mailbox Mailbox, after time.Time, keyword string, maxThreads int) ([]ICloudSyncedMessage, error) {
			return NewICloudClient().SyncMailboxMessages(ctx, session, mailbox, after, keyword, maxThreads)
		}
	}
	messages, err := syncFn(ctx, session, mailbox, after, keyword, mailboxSyncThreadLimit(mailbox))
	if err != nil {
		return 0, err
	}
	synced := 0
	lastSyncUID := mailbox.LastSyncUID
	lastSyncAt := time.Now()
	latestMessageAt := mailbox.LastSyncAt
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
		if msg.ReceivedAt.After(latestMessageAt) {
			latestMessageAt = msg.ReceivedAt
			lastSyncUID = firstNonEmpty(msg.UID, msg.RemoteID)
		}
	}
	if _, err := s.store.SetMailboxSyncCursor(mailbox.ID, lastSyncAt, lastSyncUID); err != nil {
		return synced, err
	}
	return synced, nil
}

func (s *Server) syncMailboxBatchForOwner(ctx context.Context, ownerID string, mailboxes []Mailbox, after time.Time, keyword string) error {
	if len(mailboxes) == 0 {
		return nil
	}
	release, err := s.acquireMailboxSyncSlot(ctx, ownerID)
	if err != nil {
		return err
	}
	defer release()

	refreshed := make([]Mailbox, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		latest, ok := s.store.FindMailboxByID(mailbox.ID)
		if !ok {
			continue
		}
		refreshed = append(refreshed, latest)
	}
	if len(refreshed) == 0 {
		return nil
	}
	if err := s.waitMailboxSyncInterval(ctx, ownerID); err != nil {
		return err
	}
	defer s.markMailboxSyncFinished(ownerID)
	syncFn := s.syncMailboxBatch
	if syncFn == nil {
		syncFn = func(ctx context.Context, session ICloudSession, mailboxes []Mailbox, after time.Time, keyword string, maxThreads int) (map[string][]ICloudSyncedMessage, error) {
			return NewICloudClient().SyncMailboxMessagesBatch(ctx, session, mailboxes, after, keyword, maxThreads)
		}
	}
	type sessionGroup struct {
		session   ICloudSession
		mailboxes []Mailbox
	}
	groups := make(map[string]*sessionGroup)
	order := make([]string, 0)
	for _, mailbox := range refreshed {
		session, ok := s.sessionForMailbox(ownerID, mailbox.AccountID)
		if !ok {
			return errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
		}
		key := firstNonEmpty(session.AccountID, session.DSID, session.AppleID, "__legacy__")
		group := groups[key]
		if group == nil {
			group = &sessionGroup{session: session}
			groups[key] = group
			order = append(order, key)
		}
		group.mailboxes = append(group.mailboxes, mailbox)
	}
	now := time.Now()
	for _, key := range order {
		group := groups[key]
		messagesByMailbox, err := syncFn(ctx, group.session, group.mailboxes, after, keyword, mailboxBatchThreadLimit(group.mailboxes))
		if err != nil {
			return err
		}
		for _, mailbox := range group.mailboxes {
			lastSyncUID := mailbox.LastSyncUID
			latestMessageAt := mailbox.LastSyncAt
			for _, msg := range messagesByMailbox[mailbox.ID] {
				if extractOTP(msg.Subject+"\n"+msg.Body) == "" {
					continue
				}
				_, _, err := s.store.UpsertMessage(mailbox.ID, msg.RemoteID, "icloud", msg.Subject, msg.From, msg.Body, msg.ReceivedAt)
				if err != nil {
					return err
				}
				if msg.ReceivedAt.After(latestMessageAt) {
					latestMessageAt = msg.ReceivedAt
					lastSyncUID = firstNonEmpty(msg.UID, msg.RemoteID)
				}
			}
			if _, err := s.store.SetMailboxSyncCursor(mailbox.ID, now, lastSyncUID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) acquireMailboxSyncSlot(ctx context.Context, ownerID string) (func(), error) {
	key := mailboxSyncOwnerKey(ownerID)
	s.icloudMailSyncMu.Lock()
	if s.icloudMailSyncGates == nil {
		s.icloudMailSyncGates = make(map[string]chan struct{})
	}
	gate := s.icloudMailSyncGates[key]
	if gate == nil {
		gate = make(chan struct{}, 1)
		s.icloudMailSyncGates[key] = gate
	}
	s.icloudMailSyncMu.Unlock()

	select {
	case gate <- struct{}{}:
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Server) waitMailboxSyncInterval(ctx context.Context, ownerID string) error {
	interval := mailboxMailSyncMinInterval
	if interval <= 0 {
		return nil
	}
	key := mailboxSyncOwnerKey(ownerID)
	s.icloudMailSyncMu.Lock()
	last := s.icloudMailSyncLast[key]
	s.icloudMailSyncMu.Unlock()
	if last.IsZero() {
		return nil
	}
	wait := interval - time.Since(last)
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) markMailboxSyncFinished(ownerID string) {
	key := mailboxSyncOwnerKey(ownerID)
	s.icloudMailSyncMu.Lock()
	if s.icloudMailSyncLast == nil {
		s.icloudMailSyncLast = make(map[string]time.Time)
	}
	s.icloudMailSyncLast[key] = time.Now()
	s.icloudMailSyncMu.Unlock()
}

func mailboxSyncOwnerKey(ownerID string) string {
	key := strings.TrimSpace(ownerID)
	if key == "" {
		return "__legacy__"
	}
	return key
}

func mailboxSyncThreadLimit(mailbox Mailbox) int {
	if mailbox.LastSyncAt.IsZero() {
		return 20
	}
	return 10
}

func mailboxBatchThreadLimit(mailboxes []Mailbox) int {
	limit := 20
	for _, mailbox := range mailboxes {
		if mailbox.LastSyncAt.IsZero() {
			limit = 50
			break
		}
	}
	if len(mailboxes) >= 5 && limit < 50 {
		limit = 50
	}
	return limit
}

func (s *Server) createICloudMailboxForOwner(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
	session, ok := s.sessionForOwnerAccount(ownerID, accountID)
	if !ok {
		return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
	}
	accountID = firstNonEmpty(strings.TrimSpace(accountID), session.AccountID)
	remote, err := s.createICloudMailboxRemote(ctx, ownerID, session, label, note)
	if err != nil {
		return Mailbox{}, ICloudRemoteMailbox{}, err
	}
	storeNote := strings.TrimSpace(remote.Note)
	if storeNote == "" {
		storeNote = "created by iCloud protocol"
	}
	mailbox, err := s.store.AddMailboxForOwner(ownerID, accountID, remote.Label, remote.Email)
	if err != nil {
		return Mailbox{}, remote, err
	}
	if storeNote != "" {
		updated, updateErr := s.store.SetMailboxStatus(mailbox.ID, nil, nil, StatusAvailable, storeNote)
		if updateErr == nil {
			mailbox = updated
		}
	}
	return mailbox, remote, nil
}

func (s *Server) createMailboxesForOwner(ctx context.Context, ownerID, accountID, label, note string) ([]Mailbox, []ICloudRemoteMailbox, []createMailboxFailure, error) {
	sessions := s.sessionsForOwner(ownerID, accountID)
	if len(sessions) == 0 {
		return nil, nil, nil, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
	}
	mailboxes := make([]Mailbox, 0, len(sessions))
	remotes := make([]ICloudRemoteMailbox, 0, len(sessions))
	failures := make([]createMailboxFailure, 0)
	var firstErr error
	for _, session := range sessions {
		effectiveAccountID := firstNonEmpty(strings.TrimSpace(accountID), session.AccountID)
		mailbox, remote, err := s.createMailboxForOwner(ctx, ownerID, effectiveAccountID, label, note)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			failures = append(failures, createMailboxFailure{
				AccountID: effectiveAccountID,
				AppleID:   maskAppleID(session.AppleID),
				Error:     err.Error(),
			})
			continue
		}
		mailboxes = append(mailboxes, mailbox)
		remotes = append(remotes, remote)
	}
	if len(mailboxes) == 0 && firstErr != nil {
		return mailboxes, remotes, failures, firstErr
	}
	return mailboxes, remotes, failures, nil
}

func (s *Server) createICloudMailboxRemote(ctx context.Context, ownerID string, session ICloudSession, label, note string) (ICloudRemoteMailbox, error) {
	key := strings.TrimSpace(ownerID)
	if key == "" {
		key = "global"
	}
	key += ":" + firstNonEmpty(session.AccountID, session.DSID, session.AppleID, "default")

	s.icloudCreateMu.Lock()
	defer s.icloudCreateMu.Unlock()

	now := time.Now()
	if cooldownUntil := s.icloudCreateCooldown[key]; cooldownUntil.After(now) {
		remaining := int(cooldownUntil.Sub(now).Round(time.Second).Seconds())
		if remaining < 1 {
			remaining = 1
		}
		return ICloudRemoteMailbox{}, errCode("icloud_hme_limit", fmt.Sprintf("iCloud 创建上限冷却中，请约 %d 秒后再试", remaining), true)
	} else if !cooldownUntil.IsZero() {
		delete(s.icloudCreateCooldown, key)
	}

	if last := s.icloudCreateLast[key]; !last.IsZero() {
		if wait := last.Add(mailboxCreateMinInterval).Sub(now); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ICloudRemoteMailbox{}, ctx.Err()
			case <-timer.C:
			}
		}
	}

	remote, err := NewICloudClient().CreatePrivacyMailbox(ctx, session, label, note)
	s.icloudCreateLast[key] = time.Now()
	var coded codedError
	if errors.As(err, &coded) && coded.code == "icloud_hme_limit" {
		s.icloudCreateCooldown[key] = time.Now().Add(mailboxCreateLimitCooldown)
	}
	return remote, err
}

func (s *Server) logICloudCreateError(ownerID string, err error) {
	var coded codedError
	if errors.As(err, &coded) {
		s.logger.Warn("iCloud mailbox create failed", "owner", s.ownerName(ownerID), "code", coded.code, "retryable", coded.retryable)
		return
	}
	s.logger.Warn("iCloud mailbox create failed", "owner", s.ownerName(ownerID), "err", err)
}

func (s *Server) authorized(r *http.Request, mailbox Mailbox) bool {
	queryKey := strings.TrimSpace(r.URL.Query().Get("key"))
	if constantTimeEqual(queryKey, mailbox.APIToken) {
		return true
	}
	candidates := []string{
		strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		r.Header.Get("X-API-Key"),
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
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if constantTimeEqual(candidate, want) {
			return true
		}
	}
	return false
}

func scopedOwnerID(r *http.Request, store *FileStore) string {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		session, user, ok := store.WebSessionByToken(cookie.Value)
		if ok && !session.IsAdmin && user.ID != "" {
			return user.ID
		}
	}
	return ""
}

func requestOwnerID(r *http.Request, store *FileStore) string {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_, user, ok := store.WebSessionByToken(cookie.Value)
		if ok && user.ID != "" {
			return user.ID
		}
	}
	return ""
}

func (s *Server) scopedState(r *http.Request) State {
	if s.isAdminRequest(r) {
		return s.store.Snapshot()
	}
	if key := scopedOwnerID(r, s.store); key != "" {
		return s.store.SnapshotForOwner(key)
	}
	return s.store.Snapshot()
}

func (s *Server) sessionForRequest(r *http.Request) (ICloudSession, bool) {
	session, _, ok := s.sessionForRequestWithOwner(r)
	return session, ok
}

func (s *Server) sessionForOwner(ownerID string) (ICloudSession, bool) {
	if ownerID = strings.TrimSpace(ownerID); ownerID != "" {
		return s.store.ICloudSessionForOwner(ownerID)
	}
	return s.store.ICloudSession()
}

func (s *Server) sessionForOwnerAccount(ownerID, accountID string) (ICloudSession, bool) {
	if ownerID = strings.TrimSpace(ownerID); ownerID != "" {
		if session, ok := s.store.ICloudSessionForOwnerAccount(ownerID, accountID); ok {
			return session, true
		}
		if user, ok := s.store.UserByID(ownerID); ok && user.IsAdmin {
			return s.store.ICloudSessionForOwnerAccount("", accountID)
		}
		return ICloudSession{}, false
	}
	return s.store.ICloudSessionForOwnerAccount("", accountID)
}

func (s *Server) sessionsForOwner(ownerID, accountID string) []ICloudSession {
	accountID = strings.TrimSpace(accountID)
	if accountID != "" {
		if session, ok := s.sessionForOwnerAccount(ownerID, accountID); ok {
			return []ICloudSession{session}
		}
		return nil
	}
	if ownerID = strings.TrimSpace(ownerID); ownerID != "" {
		sessions := s.store.ICloudSessionsForOwner(ownerID)
		if len(sessions) > 0 {
			return sessions
		}
		if user, ok := s.store.UserByID(ownerID); ok && user.IsAdmin {
			return s.store.ICloudSessionsForOwner("")
		}
		return nil
	}
	return s.store.ICloudSessionsForOwner("")
}

func (s *Server) sessionForMailbox(ownerID, accountID string) (ICloudSession, bool) {
	if session, ok := s.sessionForOwnerAccount(ownerID, accountID); ok {
		return session, true
	}
	sessions := s.sessionsForOwner(ownerID, "")
	if len(sessions) == 1 {
		return sessions[0], true
	}
	return ICloudSession{}, false
}

func (s *Server) publicSessionForRequest(r *http.Request) publicICloudSession {
	session, ok := s.sessionForRequest(r)
	if !ok {
		return publicSession(nil)
	}
	return publicSession(&session)
}

func (s *Server) publicSessionsForRequest(r *http.Request) []publicICloudSession {
	return s.publicSessionsForOwner(requestOwnerID(r, s.store))
}

func (s *Server) publicSessionsForOwner(ownerID string) []publicICloudSession {
	sessions := s.sessionsForOwner(ownerID, "")
	out := make([]publicICloudSession, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, publicSession(&session))
	}
	return out
}

func (s *Server) sessionForRequestWithOwner(r *http.Request) (ICloudSession, string, bool) {
	if ownerID := requestOwnerID(r, s.store); ownerID != "" {
		if session, ok := s.store.ICloudSessionForOwner(ownerID); ok {
			return session, ownerID, true
		}
	}
	if s.isAdminRequest(r) {
		session, ok := s.store.ICloudSession()
		return session, "", ok
	}
	ownerID := scopedOwnerID(r, s.store)
	session, ok := s.store.ICloudSessionForOwner(ownerID)
	return session, ownerID, ok
}

func (s *Server) currentWebSession(r *http.Request) (WebSession, User, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return WebSession{}, User{}, false
	}
	return s.store.WebSessionByToken(cookie.Value)
}

func (s *Server) authorizedUserSession(r *http.Request) bool {
	session, user, ok := s.currentWebSession(r)
	return ok && !session.IsAdmin && user.ID != ""
}

func (s *Server) authorizedAdminSession(r *http.Request) bool {
	session, user, ok := s.currentWebSession(r)
	return ok && (session.IsAdmin || user.IsAdmin)
}

func (s *Server) isAdminRequest(r *http.Request) bool {
	return s.authorizedAdminSession(r)
}

func (s *Server) allowsUserSession(r *http.Request) bool {
	if r.Method == http.MethodGet && r.URL.Path == "/api/status" {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/manage/data" {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/runtime/export" {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/runtime/export-mailbox-apis" {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/runtime/export-mailbox-emails" {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/icloud/session" {
		return true
	}
	if r.Method == http.MethodPost {
		switch r.URL.Path {
		case "/api/icloud/protocol-login/start",
			"/api/icloud/protocol-login/2fa",
			"/api/icloud/session/check",
			"/api/icloud/mailboxes/create",
			"/api/icloud/mailboxes/sync",
			"/api/icloud/scheduler/start",
			"/api/icloud/scheduler/stop":
			return true
		}
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/icloud/scheduler/status" {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/accounts" {
		return true
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/accounts" {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/mailboxes" {
		return true
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/mailboxes" {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/mailboxes/") {
		return true
	}
	return false
}

func (s *Server) canAccessMailboxID(r *http.Request, id string) bool {
	mailbox, ok := s.store.FindMailboxByID(id)
	return ok && s.canAccessMailbox(r, mailbox)
}

func (s *Server) canAccessMailbox(r *http.Request, mailbox Mailbox) bool {
	if s.isAdminRequest(r) {
		return true
	}
	ownerID := scopedOwnerID(r, s.store)
	if ownerID == "" {
		return true
	}
	return constantTimeEqual(ownerID, mailbox.OwnerID)
}

func (s *Server) canAccessAccountID(r *http.Request, id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return true
	}
	if s.isAdminRequest(r) {
		return true
	}
	ownerID := scopedOwnerID(r, s.store)
	if ownerID == "" {
		return true
	}
	state := s.store.SnapshotForOwner(ownerID)
	for _, account := range state.Accounts {
		if account.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) canAccessAccountIDForOwner(ownerID, id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return true
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return true
	}
	state := s.store.SnapshotForOwner(ownerID)
	for _, account := range state.Accounts {
		if account.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) requiresAdmin(r *http.Request) bool {
	if r.URL.Path == "/" {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/api/auth/") {
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

func constantTimeEqual(candidate, want string) bool {
	candidate = strings.TrimSpace(candidate)
	want = strings.TrimSpace(want)
	if candidate == "" || want == "" || len(candidate) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(want)) == 1
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) secureCookie(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s.cfg.PublicBaseURL)), "https://")
}

func publicUserFromUser(user User) publicUser {
	return publicUser{
		ID:          user.ID,
		Username:    user.Username,
		Status:      user.Status,
		IsAdmin:     user.IsAdmin,
		CreatedAt:   formatTime(user.CreatedAt),
		UpdatedAt:   formatTime(user.UpdatedAt),
		LastLoginAt: formatTime(user.LastLoginAt),
	}
}

func (s *Server) ownerName(ownerID string) string {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return "管理员/全局"
	}
	if user, ok := s.store.UserByID(ownerID); ok {
		return user.Username
	}
	return "旧数据/未知归属"
}

func (s *Server) publicUserSummaries(users []User, state State) []publicUserSummary {
	type counter struct {
		publicUserSummary
	}
	rows := make(map[string]*counter, len(users)+1)
	order := make([]string, 0, len(users)+1)

	ensure := func(ownerID, username string) *counter {
		ownerID = strings.TrimSpace(ownerID)
		if row, ok := rows[ownerID]; ok {
			if row.Username == "" && username != "" {
				row.Username = username
			}
			return row
		}
		if username == "" {
			username = s.ownerName(ownerID)
		}
		row := &counter{publicUserSummary: publicUserSummary{
			OwnerID:  ownerID,
			Username: username,
			Status:   StatusActive,
		}}
		rows[ownerID] = row
		order = append(order, ownerID)
		return row
	}

	for _, user := range users {
		row := ensure(user.ID, user.Username)
		row.Status = user.Status
		row.IsAdmin = user.IsAdmin
		row.LastLoginAt = formatTime(user.LastLoginAt)
	}

	mailboxOwner := make(map[string]string, len(state.Mailboxes))
	for _, account := range state.Accounts {
		ensure(account.OwnerID, "").AccountCount++
	}
	for _, mailbox := range state.Mailboxes {
		row := ensure(mailbox.OwnerID, "")
		row.MailboxCount++
		switch mailbox.Status {
		case StatusAvailable:
			row.AvailableMailboxCount++
		case StatusUsed:
			row.UsedMailboxCount++
		}
		mailboxOwner[mailbox.ID] = mailbox.OwnerID
	}
	for _, msg := range state.Messages {
		ownerID := strings.TrimSpace(msg.OwnerID)
		if ownerID == "" {
			ownerID = mailboxOwner[msg.MailboxID]
		}
		ensure(ownerID, "").MessageCount++
	}
	if state.ICloudSession != nil && len(state.ICloudSession.Cookies) > 0 {
		ensure("", "管理员/全局").ICloudSessionSaved = true
	}
	for _, session := range state.ICloudSessions {
		if len(session.Cookies) > 0 {
			ensure(session.OwnerID, "").ICloudSessionSaved = true
		}
	}

	out := make([]publicUserSummary, 0, len(order))
	for _, ownerID := range order {
		row := rows[ownerID]
		if ownerID == "" && row.AccountCount == 0 && row.MailboxCount == 0 && row.MessageCount == 0 && !row.ICloudSessionSaved {
			continue
		}
		out = append(out, row.publicUserSummary)
	}
	return out
}

func (s *Server) publicAccount(account Account) publicAccount {
	return publicAccount{
		ID:           account.ID,
		OwnerID:      account.OwnerID,
		Owner:        s.ownerName(account.OwnerID),
		Label:        account.Label,
		AppleID:      maskAppleID(account.AppleID),
		Status:       account.Status,
		ICloudStatus: account.ICloudStatus,
		Note:         account.Note,
		CreatedAt:    formatTime(account.CreatedAt),
		UpdatedAt:    formatTime(account.UpdatedAt),
	}
}

func (s *Server) publicMailbox(r *http.Request, mailbox Mailbox) publicMailbox {
	accountLabel := ""
	accountAppleID := ""
	if strings.TrimSpace(mailbox.AccountID) != "" {
		if account, ok := s.store.FindAccountByID(mailbox.AccountID); ok {
			accountLabel = account.Label
			accountAppleID = maskAppleID(account.AppleID)
		}
	}
	return publicMailbox{
		ID:             mailbox.ID,
		OwnerID:        mailbox.OwnerID,
		Owner:          s.ownerName(mailbox.OwnerID),
		AccountID:      mailbox.AccountID,
		AccountLabel:   accountLabel,
		AccountAppleID: accountAppleID,
		Label:          mailbox.Label,
		Email:          mailbox.Email,
		APITokenMask:   maskSecret(mailbox.APIToken, 6),
		APIURL:         s.mailboxAPIURL(r, mailbox),
		APIActive:      mailbox.APIActive,
		ICloudActive:   mailbox.ICloudActive,
		ReceiveCount:   mailbox.ReceiveCount,
		Status:         mailbox.Status,
		Note:           mailbox.Note,
		LastSyncAt:     formatTime(mailbox.LastSyncAt),
		LastSyncUID:    mailbox.LastSyncUID,
		CreatedAt:      formatTime(mailbox.CreatedAt),
		UpdatedAt:      formatTime(mailbox.UpdatedAt),
	}
}

func (s *Server) mailboxAPIURL(r *http.Request, mailbox Mailbox) string {
	baseURL := firstNonEmpty(s.cfg.PublicBaseURL, requestBaseURL(r))
	return fmt.Sprintf("%s/api/v1/mailboxes/%s/code?key=%s", strings.TrimRight(baseURL, "/"), url.PathEscape(mailbox.Email), url.QueryEscape(mailbox.APIToken))
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
		AccountID:          session.AccountID,
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

func publicSessionForAppleID(sessions []publicICloudSession, appleID string) publicICloudSession {
	masked := maskAppleID(appleID)
	for _, session := range sessions {
		if masked != "" && session.AppleID == masked {
			return session
		}
	}
	if len(sessions) > 0 {
		return sessions[0]
	}
	return publicSession(nil)
}

func firstMap(rows []map[string]any) map[string]any {
	if len(rows) == 0 {
		return map[string]any{}
	}
	return rows[0]
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
