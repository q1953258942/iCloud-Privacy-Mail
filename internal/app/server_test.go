package app

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtractOTP(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "openai subject", text: "Your OpenAI code is 123456", want: "123456"},
		{name: "chinese", text: "验证码：654321，请勿泄露", want: "654321"},
		{name: "fallback", text: "Use 246810 to continue.", want: "246810"},
		{name: "zero invalid", text: "code 000000", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractOTP(tt.text); got != tt.want {
				t.Fatalf("extractOTP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCookieHeaderFiltersByDomainAndExpiry(t *testing.T) {
	cookies := []SessionCookie{
		{Name: "ok", Value: "1", Domain: ".icloud.com.cn", Path: "/"},
		{Name: "other", Value: "2", Domain: ".example.com", Path: "/"},
		{Name: "expired", Value: "3", Domain: ".icloud.com.cn", Path: "/", Expires: 1},
	}
	got := cookieHeader(cookies, "https://p213-maildomainws.icloud.com.cn/v1/hme/generate")
	if got != "ok=1" {
		t.Fatalf("cookieHeader() = %q, want ok=1", got)
	}
}

func TestICloudEndpointAddsProtocolQuery(t *testing.T) {
	client := NewICloudClient()
	got, err := client.endpoint(ICloudSession{
		PremiumMailBaseURL: "https://p213-maildomainws.icloud.com.cn:443",
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
	}, "/v1/hme/generate")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"https://p213-maildomainws.icloud.com.cn:443/v1/hme/generate?",
		"clientBuildNumber=build",
		"clientMasteringNumber=master",
		"clientId=cid",
		"dsid=123",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("endpoint %q missing %q", got, want)
		}
	}
}

func TestMailGatewayBaseURLFallback(t *testing.T) {
	got, err := mailGatewayBaseURL(ICloudSession{MailBaseURL: "https://p213-mailws.icloud.com.cn:443"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://p213-mccgateway.icloud.com.cn:443" {
		t.Fatalf("mailGatewayBaseURL() = %q", got)
	}

	got, err = mailGatewayBaseURL(ICloudSession{PremiumMailBaseURL: "https://p213-maildomainws.icloud.com.cn:443"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://p213-mccgateway.icloud.com.cn:443" {
		t.Fatalf("mailGatewayBaseURL() from premium = %q", got)
	}
}

func TestPublicSessionIncludesLastCheckStatus(t *testing.T) {
	checkedAt := time.Date(2026, 6, 21, 23, 0, 0, 0, time.UTC)
	session := ICloudSession{
		SavedAt:           checkedAt.Add(-time.Hour),
		AppleID:           "user@example.com",
		DSID:              "1234567890",
		IsICloudPlus:      true,
		CanCreateHME:      true,
		Cookies:           []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com.cn", Path: "/"}},
		LastCheckedAt:     checkedAt,
		LastCheckOK:       false,
		LastStatusMessage: "最近检测失败：请重新登录",
	}
	got := publicSession(&session)
	if got.LastCheckedAt != formatTime(checkedAt) {
		t.Fatalf("LastCheckedAt = %q, want %q", got.LastCheckedAt, formatTime(checkedAt))
	}
	if got.LastCheckOK {
		t.Fatalf("LastCheckOK = true, want false")
	}
	if got.LastStatusMessage != session.LastStatusMessage {
		t.Fatalf("LastStatusMessage = %q, want %q", got.LastStatusMessage, session.LastStatusMessage)
	}
}

func TestUpsertMessageDeduplicatesRemoteID(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.UpsertMessage(mailbox.ID, "remote-1", "icloud", "code 123456", "noreply", "first", zeroTime()); err != nil || !created {
		t.Fatalf("first upsert created=%v err=%v", created, err)
	}
	if _, created, err := store.UpsertMessage(mailbox.ID, "remote-1", "icloud", "code 654321", "noreply", "updated", zeroTime()); err != nil || created {
		t.Fatalf("second upsert created=%v err=%v", created, err)
	}
	state := store.Snapshot()
	if len(state.Messages) != 1 {
		t.Fatalf("messages len = %d, want 1", len(state.Messages))
	}
	if state.Messages[0].Body != "updated" {
		t.Fatalf("message body = %q", state.Messages[0].Body)
	}
	if state.Mailboxes[0].ReceiveCount != 1 {
		t.Fatalf("receive_count = %d, want 1", state.Mailboxes[0].ReceiveCount)
	}
}

func TestFileStoreSetPathMigratesAndLoadsState(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddAccount("UPI-1", "user@example.com", ""); err != nil {
		t.Fatal(err)
	}
	nextPath := filepath.Join(t.TempDir(), "custom-data", "state.json")
	state, err := store.SetPath(nextPath)
	if err != nil {
		t.Fatal(err)
	}
	if store.Path() != nextPath {
		t.Fatalf("Path() = %q, want %q", store.Path(), nextPath)
	}
	if len(state.Accounts) != 1 {
		t.Fatalf("migrated accounts = %d, want 1", len(state.Accounts))
	}

	other := newTestStore(t)
	if _, err := other.AddMailbox("", "UPI-2", "alias@icloud.com"); err != nil {
		t.Fatal(err)
	}
	otherPath := other.Path()
	loaded, err := store.SetPath(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Mailboxes) != 1 || loaded.Mailboxes[0].Email != "alias@icloud.com" {
		t.Fatalf("loaded state = %+v", loaded)
	}
}

func TestRuntimeExportIncludesAccountsMailboxesAndSession(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddAccount("UPI-1", "user@example.com", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailbox("", "UPI-2", "alias@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSession(ICloudSession{DSID: "123", Cookies: []SessionCookie{{Name: "session", Value: "x"}}}); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Accounts      []Account      `json:"accounts"`
		Mailboxes     []Mailbox      `json:"mailboxes"`
		ICloudSession *ICloudSession `json:"icloud_session"`
		Messages      []Message      `json:"messages"`
		MessageCount  int            `json:"message_count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Accounts) != 1 || len(body.Mailboxes) != 1 || body.ICloudSession == nil {
		t.Fatalf("export body = %+v", body)
	}
	if len(body.Messages) != 0 || body.MessageCount != 0 {
		t.Fatalf("messages exported by default = %d count=%d", len(body.Messages), body.MessageCount)
	}
}

func TestBrowserKeyScopesManagementDataAndExport(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{AdminKey: "admin-secret", PublicBaseURL: "https://mail.example"}, store, discardLogger())

	keyA := requestTestBrowserKey(t, handler)
	keyB := requestTestBrowserKey(t, handler)
	createTestMailbox(t, handler, keyA, "UPI-A", "a@icloud.com")
	createTestMailbox(t, handler, keyB, "UPI-B", "b@icloud.com")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/mailboxes", nil)
	req.Header.Set("X-Browser-Key", keyA)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list with browser key = %d body=%s", rr.Code, rr.Body.String())
	}
	var listBody struct {
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listBody); err != nil {
		t.Fatal(err)
	}
	if len(listBody.Mailboxes) != 1 || listBody.Mailboxes[0].Email != "a@icloud.com" {
		t.Fatalf("scoped list = %+v", listBody.Mailboxes)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/runtime/export", nil)
	req.Header.Set("X-Browser-Key", keyA)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("export with browser key = %d body=%s", rr.Code, rr.Body.String())
	}
	var exportBody struct {
		Scope     string    `json:"scope"`
		Mailboxes []Mailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &exportBody); err != nil {
		t.Fatal(err)
	}
	if exportBody.Scope != "browser" || len(exportBody.Mailboxes) != 1 || exportBody.Mailboxes[0].Email != "a@icloud.com" {
		t.Fatalf("scoped export = %+v", exportBody)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/runtime/export", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("export without admin/browser key = %d, want 401", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/runtime/export", nil)
	req.Header.Set("X-Admin-Key", "admin-secret")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin export = %d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &exportBody); err != nil {
		t.Fatal(err)
	}
	if exportBody.Scope != "all" || len(exportBody.Mailboxes) != 2 {
		t.Fatalf("admin export = %+v", exportBody)
	}
}

func TestBrowserKeyCannotMutateOtherBrowserMailbox(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{AdminKey: "admin-secret"}, store, discardLogger())

	keyA := requestTestBrowserKey(t, handler)
	keyB := requestTestBrowserKey(t, handler)
	mailboxB := createTestMailbox(t, handler, keyB, "UPI-B", "b@icloud.com")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailboxB.ID+"/status", strings.NewReader(`{"status":"used"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Browser-Key", keyA)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("other browser mutate = %d body=%s, want 404", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailboxB.ID+"/status", strings.NewReader(`{"status":"used"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Browser-Key", keyB)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("owner browser mutate = %d body=%s", rr.Code, rr.Body.String())
	}
	updated, ok := store.FindMailboxByID(mailboxB.ID)
	if !ok || updated.Status != StatusUsed {
		t.Fatalf("stored mailbox = %+v ok=%v", updated, ok)
	}
}

func TestBrowserKeyCannotUseBrowserFallbackEndpoints(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{AdminKey: "admin-secret"}, store, discardLogger())
	browserKey := requestTestBrowserKey(t, handler)

	tests := []struct {
		name string
		path string
		body string
	}{
		{
			name: "open bitbrowser",
			path: "/api/icloud/browser/open",
			body: `{"browser_id":"local-browser"}`,
		},
		{
			name: "save cdp session",
			path: "/api/icloud/session/save",
			body: `{"cdp_http":"127.0.0.1:9222"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Browser-Key", browserKey)
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("%s with browser key = %d body=%s, want 401", tt.path, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestSensitiveKeysAreNotAcceptedFromQueryString(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{AdminKey: "admin-secret", APIKey: "global-secret"}, store, discardLogger())
	browserKey := requestTestBrowserKey(t, handler)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "admin key query rejected",
			method: http.MethodGet,
			path:   "/api/status?admin_key=admin-secret",
		},
		{
			name:   "browser key query rejected",
			method: http.MethodGet,
			path:   "/api/status?browser_key=" + browserKey,
		},
		{
			name:   "global api key query rejected on claim",
			method: http.MethodPost,
			path:   "/api/v1/mailboxes/claim?key=global-secret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s = %d body=%s, want 401", tt.method, tt.path, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestMailboxCodeQueryAcceptsOnlyPerMailboxToken(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "Your OpenAI code is 135790", "noreply@example.com", "Use 135790 to continue.", time.Now()); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{APIKey: "global-secret"}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/alias%40icloud.com/code?key=global-secret&after=2000-01-01T00:00:00Z", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code with global query key = %d body=%s, want 401", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/alias%40icloud.com/code?key="+mailbox.APIToken+"&after=2000-01-01T00:00:00Z", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code with mailbox query key = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "135790" {
		t.Fatalf("code body = %+v", body)
	}
}

func TestLatestMailboxCodeSelectsNewestAndHonorsAfter(t *testing.T) {
	oldTime := time.Date(2026, 6, 21, 21, 36, 50, 0, time.FixedZone("CST", 8*3600))
	newTime := oldTime.Add(30 * time.Minute)
	messages := []Message{
		{ID: "old", Subject: "Your temporary ChatGPT verification code", Body: "Enter this temporary verification code to continue: 733849", ReceivedAt: oldTime},
		{ID: "new", Subject: "Your temporary ChatGPT verification code", Body: "Enter this temporary verification code to continue: 246810", ReceivedAt: newTime},
	}

	msg, code, ok := latestMailboxCode(messages, time.Time{}, "ChatGPT")
	if !ok || msg.ID != "new" || code != "246810" {
		t.Fatalf("latestMailboxCode() msg=%s code=%q ok=%v, want new 246810 true", msg.ID, code, ok)
	}

	msg, code, ok = latestMailboxCode(messages, newTime.Add(-time.Minute), "ChatGPT")
	if !ok || msg.ID != "new" || code != "246810" {
		t.Fatalf("latestMailboxCode(after) msg=%s code=%q ok=%v, want new 246810 true", msg.ID, code, ok)
	}

	_, _, ok = latestMailboxCode(messages, newTime.Add(time.Minute), "ChatGPT")
	if ok {
		t.Fatalf("latestMailboxCode(after future) ok=true, want false")
	}
}

func TestLatestMailboxCodeUsesCreatedAtWhenReceivedAtMissing(t *testing.T) {
	messages := []Message{
		{ID: "old", Subject: "ChatGPT code", Body: "code 111111", CreatedAt: time.Date(2026, 6, 21, 20, 0, 0, 0, time.UTC)},
		{ID: "new", Subject: "ChatGPT code", Body: "code 222222", CreatedAt: time.Date(2026, 6, 21, 20, 5, 0, 0, time.UTC)},
	}

	msg, code, ok := latestMailboxCode(messages, time.Time{}, "ChatGPT")
	if !ok || msg.ID != "new" || code != "222222" {
		t.Fatalf("latestMailboxCode() msg=%s code=%q ok=%v, want new 222222 true", msg.ID, code, ok)
	}
}

func TestAdminKeyProtectsManagementAPI(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{AdminKey: "admin-secret"}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status without admin = %d, want 401", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("X-Admin-Key", "admin-secret")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status with admin = %d, want 200", rr.Code)
	}
}

func TestClaimMailboxRequiresGlobalAPIKeyAndMarksUsed(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{APIKey: "global-key", PublicBaseURL: "https://mail.example"}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/claim", strings.NewReader(`{"project":"openai","purpose":"register"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("claim without key = %d, want 401", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/claim", strings.NewReader(`{"project":"openai","purpose":"register"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer global-key")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("claim with key = %d, body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool          `json:"success"`
		Mailbox publicMailbox `json:"mailbox"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Mailbox.ID != mailbox.ID || body.Mailbox.Status != StatusUsed {
		t.Fatalf("claim body = %+v", body)
	}
	if !strings.HasPrefix(body.Mailbox.APIURL, "https://mail.example/") {
		t.Fatalf("api_url = %q", body.Mailbox.APIURL)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || updated.Status != StatusUsed {
		t.Fatalf("stored mailbox = %+v ok=%v", updated, ok)
	}
}

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func requestTestBrowserKey(t *testing.T, handler http.Handler) string {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/browser-key", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("browser key status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		BrowserKey string `json:"browser_key"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.BrowserKey == "" {
		t.Fatalf("empty browser key")
	}
	return body.BrowserKey
}

func createTestMailbox(t *testing.T, handler http.Handler, browserKey, label, email string) publicMailbox {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes", strings.NewReader(`{"label":"`+label+`","email":"`+email+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Browser-Key", browserKey)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create mailbox %s = %d body=%s", email, rr.Code, rr.Body.String())
	}
	var body struct {
		Mailbox publicMailbox `json:"mailbox"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Mailbox
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func zeroTime() time.Time {
	return time.Time{}
}
