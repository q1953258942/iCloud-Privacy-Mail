package app

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

//go:embed templates/index.html
var webFS embed.FS

type Server struct {
	cfg    Config
	store  *FileStore
	logger *slog.Logger
	mux    *http.ServeMux
}

func NewServer(cfg Config, store *FileStore, logger *slog.Logger) http.Handler {
	s := &Server{
		cfg:    cfg,
		store:  store,
		logger: logger,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /", s.handleHome)
	s.mux.HandleFunc("GET /api/status", s.handleStatus)
	s.mux.HandleFunc("GET /api/accounts", s.handleListAccounts)
	s.mux.HandleFunc("POST /api/accounts", s.handleCreateAccount)
	s.mux.HandleFunc("GET /api/mailboxes", s.handleListMailboxes)
	s.mux.HandleFunc("POST /api/mailboxes", s.handleCreateMailbox)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/verify", s.handleVerifyMailbox)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/disable", s.handleDisableMailbox)
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
		"base_url":           requestBaseURL(r),
		"accounts":           len(state.Accounts),
		"mailboxes":          len(state.Mailboxes),
		"messages":           len(state.Messages),
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

	messages := s.store.MessagesForMailbox(mailbox.ID)
	for i := len(messages) - 1; i >= 0; i-- {
		msg := messages[i]
		if !after.IsZero() && msg.ReceivedAt.Before(after.Add(-10*time.Second)) {
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
		writeJSON(w, http.StatusOK, map[string]any{
			"success":     true,
			"email":       mailbox.Email,
			"code":        code,
			"subject":     msg.Subject,
			"received_at": formatTime(msg.ReceivedAt),
			"message_id":  msg.ID,
		})
		return
	}
	writeError(w, http.StatusOK, errCode("no_code", "暂未收到验证码", true))
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
		if candidate == mailbox.APIToken {
			return true
		}
		if s.cfg.APIKey != "" && candidate == s.cfg.APIKey {
			return true
		}
	}
	return false
}

func (s *Server) publicMailbox(r *http.Request, mailbox Mailbox) publicMailbox {
	apiURL := fmt.Sprintf("%s/api/v1/mailboxes/%s/code?key=%s", requestBaseURL(r), url.PathEscape(mailbox.Email), url.QueryEscape(mailbox.APIToken))
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
