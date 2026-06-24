package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

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

func TestAppleDomainRedirectMapsDomainToHost(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{domain: "iCloud.com", want: "www.icloud.com"},
		{domain: "www.icloud.com", want: "www.icloud.com"},
		{domain: "https://www.icloud.com.cn/", want: "www.icloud.com.cn"},
		{domain: "example.com", want: ""},
	}
	for _, tt := range tests {
		if got := appleDomainToHost(tt.domain); got != tt.want {
			t.Fatalf("appleDomainToHost(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestParseAppleDomainRedirect(t *testing.T) {
	redirect, ok := parseAppleDomainRedirect(http.StatusFound, []byte(`{"domainToUse":"iCloud.com"}`))
	if !ok {
		t.Fatal("parseAppleDomainRedirect did not detect redirect")
	}
	if redirect.Host != "www.icloud.com" || redirect.DomainToUse != "iCloud.com" {
		t.Fatalf("redirect = %+v, want www.icloud.com", redirect)
	}

	if _, ok := parseAppleDomainRedirect(http.StatusOK, []byte(`{"domainToUse":"iCloud.com"}`)); ok {
		t.Fatal("parseAppleDomainRedirect detected non-redirect status")
	}
}

func TestAppleAuthSessionSwitchHost(t *testing.T) {
	session := &appleAuthSession{Endpoints: appleAuthEndpointsForHost("www.icloud.com.cn")}
	if !session.switchHost("www.icloud.com") {
		t.Fatal("switchHost returned false, want true")
	}
	if session.Endpoints.Host != "www.icloud.com" || !strings.Contains(session.Endpoints.Auth, "idmsa.apple.com/appleauth") {
		t.Fatalf("endpoints after switch = %+v", session.Endpoints)
	}
	if session.switchHost("www.icloud.com") {
		t.Fatal("switchHost returned true for same host")
	}
}

func TestAppleHostForAccountCountry(t *testing.T) {
	tests := []struct {
		country string
		want    string
	}{
		{country: "", want: ""},
		{country: "CHN", want: "www.icloud.com.cn"},
		{country: "CN", want: "www.icloud.com.cn"},
		{country: "USA", want: "www.icloud.com"},
		{country: "sgp", want: "www.icloud.com"},
	}
	for _, tt := range tests {
		if got := appleHostForAccountCountry(tt.country); got != tt.want {
			t.Fatalf("appleHostForAccountCountry(%q) = %q, want %q", tt.country, got, tt.want)
		}
	}
}

func TestAppleAuthSessionRedirectForAccountCountry(t *testing.T) {
	session := &appleAuthSession{
		Endpoints:      appleAuthEndpointsForHost("www.icloud.com.cn"),
		AccountCountry: "USA",
	}
	redirect, ok := session.redirectForAccountCountry()
	if !ok {
		t.Fatal("redirectForAccountCountry returned ok=false")
	}
	if redirect.Host != "www.icloud.com" || redirect.DomainToUse != "iCloud.com" {
		t.Fatalf("redirect = %+v, want www.icloud.com", redirect)
	}

	session = &appleAuthSession{
		Endpoints:      appleAuthEndpointsForHost("www.icloud.com.cn"),
		AccountCountry: "CHN",
	}
	if _, ok := session.redirectForAccountCountry(); ok {
		t.Fatal("redirectForAccountCountry returned ok=true for matching China host")
	}
}

func TestAppleTransientNetworkErrorDetection(t *testing.T) {
	if !isAppleTransientNetworkError(&url.Error{Op: "Post", URL: "https://setup.icloud.com/setup/ws/1/accountLogin", Err: io.EOF}) {
		t.Fatal("EOF url error should be transient")
	}
	if !isAppleTransientNetworkError(fmt.Errorf("net/http: timeout awaiting response headers")) {
		t.Fatal("timeout should be transient")
	}
	if isAppleTransientNetworkError(errCode("apple_protocol_http_error", "Apple 协议 HTTP 401", true)) {
		t.Fatal("HTTP business error should not be transient")
	}
}

func TestRetryAppleTransientRetriesEOF(t *testing.T) {
	attempts := 0
	err := retryAppleTransient(t.Context(), func() error {
		attempts++
		if attempts < 2 {
			return io.EOF
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
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

func TestStatusReturnsOwnerICloudSessionForAdminUser(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, adminUser := registerTestUser(t, handler, "admin", "admin123")
	if err := store.SaveICloudSessionForOwner(adminUser.ID, ICloudSession{
		SavedAt:       time.Now(),
		AppleID:       "admin@example.com",
		DSID:          "12345678908382",
		IsICloudPlus:  true,
		CanCreateHME:  true,
		Cookies:       []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com.cn", Path: "/"}},
		LastCheckOK:   true,
		LastCheckedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		ICloudSession publicICloudSession `json:"icloud_session"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.ICloudSession.Saved || body.ICloudSession.CookieCount != 1 || !body.ICloudSession.ProviderConfigured {
		t.Fatalf("icloud session = %+v, want saved owner session", body.ICloudSession)
	}
}

func TestICloudCreateLimitErrorIsClassified(t *testing.T) {
	err := iCloudAPIError("You have reached the limit of addresses you can create right now. Please try again later.")
	coded, ok := err.(codedError)
	if !ok {
		t.Fatalf("error type = %T, want codedError", err)
	}
	if coded.code != "icloud_hme_limit" || !coded.retryable {
		t.Fatalf("coded error = %+v, want icloud_hme_limit retryable", coded)
	}
}

func TestICloudClientListPrivacyMailboxes(t *testing.T) {
	var sawRequest bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest = true
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("path = %s, want /v2/hme/list", r.URL.Path)
		}
		if r.URL.Query().Get("dsid") != "123" {
			t.Fatalf("dsid query = %q, want 123", r.URL.Query().Get("dsid"))
		}
		if r.Header.Get("Origin") != "https://www.icloud.com.cn" {
			t.Fatalf("Origin = %q, want https://www.icloud.com.cn", r.Header.Get("Origin"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"timestamp": 1,
			"result": {
				"forwardToEmails": ["main@example.com"],
				"hmeEmails": [
					{"anonymousId":"a1","hme":"Phone.Created@iCloud.com","label":"PHONE","isActive":true,"forwardToEmail":"main@example.com","origin":"ON_DEMAND"},
					{"anonymousId":"a2","hme":"old@icloud.com","isActive":false,"origin":"MAIL"}
				]
			}
		}`))
	}))
	defer ts.Close()

	client := &ICloudClient{client: ts.Client()}
	remotes, err := client.ListPrivacyMailboxes(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com.cn",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawRequest {
		t.Fatal("server did not receive request")
	}
	if len(remotes) != 2 {
		t.Fatalf("remotes len = %d, want 2", len(remotes))
	}
	if remotes[0].Email != "phone.created@icloud.com" || remotes[0].Label != "PHONE" || !remotes[0].IsActive {
		t.Fatalf("first remote = %+v", remotes[0])
	}
	if remotes[1].Email != "old@icloud.com" || remotes[1].IsActive {
		t.Fatalf("second remote = %+v", remotes[1])
	}
}

func TestICloudClientListPrivacyMailboxesRetriesEOF(t *testing.T) {
	attempts := 0
	client := &ICloudClient{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return nil, io.EOF
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{
				"success": true,
				"timestamp": 1,
				"result": {"hmeEmails": [{"anonymousId":"a1","hme":"Retry.OK@icloud.com","label":"retry","isActive":true}]}
			}`)),
			Request: r,
		}, nil
	})}}
	remotes, err := client.ListPrivacyMailboxes(t.Context(), ICloudSession{
		PremiumMailBaseURL: "https://p39-maildomainws.icloud.com:443",
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if len(remotes) != 1 || remotes[0].Email != "retry.ok@icloud.com" {
		t.Fatalf("remotes = %+v", remotes)
	}
}

func TestUpsertMailboxFromRemoteCreatesAndUpdates(t *testing.T) {
	store := newTestStore(t)
	remote := ICloudRemoteMailbox{
		AnonymousID:    "a1",
		Email:          "Phone.Created@iCloud.com",
		Label:          "PHONE",
		ForwardToEmail: "main@example.com",
		IsActive:       true,
	}
	mailbox, created, err := store.UpsertMailboxFromRemote("usr_1", "acc_1", remote, "synced from iCloud")
	if err != nil {
		t.Fatal(err)
	}
	if !created || mailbox.OwnerID != "usr_1" || mailbox.AccountID != "acc_1" || mailbox.Email != "phone.created@icloud.com" || mailbox.Status != StatusAvailable {
		t.Fatalf("created mailbox = %+v created=%v", mailbox, created)
	}
	token := mailbox.APIToken

	remote.Label = "PHONE-UPDATED"
	remote.IsActive = false
	updated, created, err := store.UpsertMailboxFromRemote("usr_1", "", remote, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatalf("second upsert created=true, want update")
	}
	if updated.ID != mailbox.ID || updated.APIToken != token || updated.Label != "PHONE-UPDATED" || updated.ICloudActive {
		t.Fatalf("updated mailbox = %+v", updated)
	}
	if len(store.Snapshot().Mailboxes) != 1 {
		t.Fatalf("mailboxes len = %d, want 1", len(store.Snapshot().Mailboxes))
	}

	_, _, err = store.UpsertMailboxFromRemote("usr_2", "", remote, "")
	coded, ok := err.(codedError)
	if !ok || coded.code != "mailbox_exists_other_owner" {
		t.Fatalf("cross owner err = %T %+v, want mailbox_exists_other_owner", err, err)
	}
}

func TestMailboxSyncAfterUsesCursorOverlap(t *testing.T) {
	now := time.Date(2026, 6, 22, 11, 0, 0, 0, time.UTC)
	mailbox := Mailbox{LastSyncAt: now.Add(-time.Minute)}
	got := mailboxSyncAfter(mailbox, now.Add(-5*time.Minute), now)
	want := now.Add(-time.Minute).Add(-mailboxSyncCursorOverlap)
	if !got.Equal(want) {
		t.Fatalf("mailboxSyncAfter() = %s, want %s", got, want)
	}

	got = mailboxSyncAfter(Mailbox{}, now.Add(-5*time.Minute), now)
	if !got.Equal(now.Add(-5 * time.Minute)) {
		t.Fatalf("mailboxSyncAfter(no cursor) = %s", got)
	}
}

func TestLooksLikeVerificationText(t *testing.T) {
	tests := []struct {
		text string
		want bool
	}{
		{text: "Your ChatGPT code is ready", want: true},
		{text: "验证码 123456", want: true},
		{text: "Ordinary newsletter", want: false},
	}
	for _, tt := range tests {
		if got := looksLikeVerificationText(tt.text, "OpenAI"); got != tt.want {
			t.Fatalf("looksLikeVerificationText(%q) = %v, want %v", tt.text, got, tt.want)
		}
	}
}

func TestSetMailboxSyncCursor(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	syncedAt := time.Date(2026, 6, 22, 11, 1, 0, 0, time.UTC)
	updated, err := store.SetMailboxSyncCursor(mailbox.ID, syncedAt, "12345")
	if err != nil {
		t.Fatal(err)
	}
	if !updated.LastSyncAt.Equal(syncedAt) || updated.LastSyncUID != "12345" {
		t.Fatalf("updated cursor = %+v", updated)
	}
	stored, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || !stored.LastSyncAt.Equal(syncedAt) || stored.LastSyncUID != "12345" {
		t.Fatalf("stored cursor = %+v ok=%v", stored, ok)
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
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export", nil)
	req.AddCookie(adminCookie)
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

func TestMailboxAPITextExportIsScoped(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	userCookie, _ := registerTestUser(t, handler, "alice", "alice123")

	adminBox := createTestMailboxWithCookie(t, handler, adminCookie, "ADMIN", "admin-alias@icloud.com")
	userBox := createTestMailboxWithCookie(t, handler, userCookie, "USER", "user-alias@icloud.com")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-apis", nil)
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("user mailbox api export status = %d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q, want text/plain", ct)
	}
	userBody := rr.Body.String()
	if !strings.Contains(userBody, userBox.Email+"----"+userBox.APIURL+"\n") {
		t.Fatalf("user export missing own mailbox api: %q", userBody)
	}
	if strings.Contains(userBody, adminBox.Email) {
		t.Fatalf("user export leaked admin mailbox: %q", userBody)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-apis", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin mailbox api export status = %d body=%s", rr.Code, rr.Body.String())
	}
	adminBody := rr.Body.String()
	for _, row := range []string{adminBox.Email + "----" + adminBox.APIURL + "\n", userBox.Email + "----" + userBox.APIURL + "\n"} {
		if !strings.Contains(adminBody, row) {
			t.Fatalf("admin export missing row %q in %q", row, adminBody)
		}
	}
}

func TestMailboxEmailExportFormatsAreScoped(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	userCookie, _ := registerTestUser(t, handler, "alice", "alice123")

	adminBox := createTestMailboxWithCookie(t, handler, adminCookie, "ADMIN", "admin-alias@icloud.com")
	userBox := createTestMailboxWithCookie(t, handler, userCookie, "USER", "user-alias@icloud.com")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-emails?format=csv", nil)
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("user mailbox email export status = %d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type = %q, want text/csv", ct)
	}
	userBody := rr.Body.String()
	if !strings.Contains(userBody, userBox.Email+"\n") {
		t.Fatalf("user export missing own email: %q", userBody)
	}
	if strings.Contains(userBody, adminBox.Email) || strings.Contains(userBody, "----") {
		t.Fatalf("user email export leaked admin/API data: %q", userBody)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-emails?format=tsv", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin mailbox email export status = %d body=%s", rr.Code, rr.Body.String())
	}
	adminBody := rr.Body.String()
	for _, email := range []string{adminBox.Email + "\n", userBox.Email + "\n"} {
		if !strings.Contains(adminBody, email) {
			t.Fatalf("admin export missing email %q in %q", email, adminBody)
		}
	}
}

func TestMailboxExportFiltersByAccountID(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	accOne, err := store.AddAccountForOwner("", "Apple One", "one@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	accTwo, err := store.AddAccountForOwner("", "Apple Two", "two@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", accOne.ID, "ONE", "one-alias@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", accTwo.ID, "TWO", "two-alias@icloud.com"); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-apis?account_id="+url.QueryEscape(accOne.ID), nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("account filtered api export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "one-alias@icloud.com----https://mail.example/api/v1/mailboxes/one-alias@icloud.com/code?key=") {
		t.Fatalf("filtered export missing account one API: %q", body)
	}
	if strings.Contains(body, "two-alias@icloud.com") {
		t.Fatalf("filtered export leaked account two: %q", body)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-emails?format=jsonl&account_id="+url.QueryEscape(accTwo.ID), nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("account filtered email export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body = rr.Body.String()
	if !strings.Contains(body, `"email":"two-alias@icloud.com"`) || strings.Contains(body, "one-alias@icloud.com") || strings.Contains(body, "/api/v1/") {
		t.Fatalf("filtered email export body = %q", body)
	}
}

func TestMailboxExportAdminOwnerAndAccountFilter(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	_, normalUser := registerTestUser(t, handler, "alice", "alice123")
	adminAcc, err := store.AddAccountForOwner("", "Admin Apple", "admin@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	userAcc, err := store.AddAccountForOwner(normalUser.ID, "User Apple", "user@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", adminAcc.ID, "ADMIN", "admin-only@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner(normalUser.ID, userAcc.ID, "USER", "user-only@icloud.com"); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-emails?owner_id="+url.QueryEscape(normalUser.ID)+"&account_id="+url.QueryEscape(userAcc.ID), nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("owner/account filtered export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "user-only@icloud.com\n") || strings.Contains(body, "admin-only@icloud.com") {
		t.Fatalf("owner/account filtered export body = %q", body)
	}
}

func TestMailboxExportRejectsInvalidFormat(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-emails?format=xlsx", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid format status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserLoginScopesDataAndFirstUserIsAdmin(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())

	adminCookie, adminUser := registerTestUser(t, handler, "admin", "admin123")
	userCookie, normalUser := registerTestUser(t, handler, "alice", "alice123")
	if !adminUser.IsAdmin {
		t.Fatalf("first registered user should be admin: %+v", adminUser)
	}
	if normalUser.IsAdmin {
		t.Fatalf("second registered user should be normal: %+v", normalUser)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin auth me = %d body=%s", rr.Code, rr.Body.String())
	}
	var me struct {
		Authenticated bool       `json:"authenticated"`
		User          publicUser `json:"user"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if !me.Authenticated || me.User.Username != "admin" || !me.User.IsAdmin {
		t.Fatalf("admin auth me = %+v", me)
	}

	createTestMailboxWithCookie(t, handler, adminCookie, "ADMIN-MBX", "admin@icloud.com")
	userMailbox := createTestMailboxWithCookie(t, handler, userCookie, "USER-MBX", "alice@icloud.com")

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/mailboxes", nil)
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("user list mailboxes = %d body=%s", rr.Code, rr.Body.String())
	}
	var userList struct {
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &userList); err != nil {
		t.Fatal(err)
	}
	if len(userList.Mailboxes) != 1 || userList.Mailboxes[0].Email != "alice@icloud.com" {
		t.Fatalf("user scoped mailboxes = %+v", userList.Mailboxes)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("user manage data = %d body=%s", rr.Code, rr.Body.String())
	}
	var userManageData struct {
		UserSummaries []publicUserSummary `json:"user_summaries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &userManageData); err != nil {
		t.Fatal(err)
	}
	if len(userManageData.UserSummaries) != 1 || userManageData.UserSummaries[0].OwnerID != normalUser.ID || userManageData.UserSummaries[0].MailboxCount != 1 {
		t.Fatalf("user summaries = %+v, want one scoped summary with one mailbox", userManageData.UserSummaries)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin manage data = %d body=%s", rr.Code, rr.Body.String())
	}
	var adminData struct {
		IsAdmin       bool                `json:"is_admin"`
		Users         []publicUser        `json:"users"`
		UserSummaries []publicUserSummary `json:"user_summaries"`
		Mailboxes     []publicMailbox     `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &adminData); err != nil {
		t.Fatal(err)
	}
	if !adminData.IsAdmin || len(adminData.Users) != 2 || len(adminData.Mailboxes) != 2 {
		t.Fatalf("admin manage data = %+v", adminData)
	}
	summaryByOwner := map[string]publicUserSummary{}
	for _, summary := range adminData.UserSummaries {
		summaryByOwner[summary.OwnerID] = summary
	}
	if summaryByOwner[adminUser.ID].MailboxCount != 1 || summaryByOwner[normalUser.ID].MailboxCount != 1 {
		t.Fatalf("admin user summaries = %+v, want both users with one mailbox", adminData.UserSummaries)
	}
	if adminData.Mailboxes[0].OwnerID == "" || adminData.Mailboxes[1].OwnerID == "" {
		t.Fatalf("mailboxes should expose owner_id for admin filtering: %+v", adminData.Mailboxes)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+userMailbox.ID+"/status", strings.NewReader(`{"status":"used"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin mutate user mailbox = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSensitiveKeysAreNotAcceptedFromQueryString(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{APIKey: "global-secret"}, store, discardLogger())

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "management query key rejected",
			method: http.MethodGet,
			path:   "/api/status?admin_key=admin-secret",
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
	now := newTime.Add(time.Minute)
	messages := []Message{
		{ID: "old", Subject: "Your temporary ChatGPT verification code", Body: "Enter this temporary verification code to continue: 733849", ReceivedAt: oldTime},
		{ID: "new", Subject: "Your temporary ChatGPT verification code", Body: "Enter this temporary verification code to continue: 246810", ReceivedAt: newTime},
	}

	msg, code, ok := latestMailboxCode(messages, time.Time{}, "ChatGPT", now)
	if !ok || msg.ID != "new" || code != "246810" {
		t.Fatalf("latestMailboxCode() msg=%s code=%q ok=%v, want new 246810 true", msg.ID, code, ok)
	}

	msg, code, ok = latestMailboxCode(messages, newTime.Add(-time.Minute), "ChatGPT", now)
	if !ok || msg.ID != "new" || code != "246810" {
		t.Fatalf("latestMailboxCode(after) msg=%s code=%q ok=%v, want new 246810 true", msg.ID, code, ok)
	}

	_, _, ok = latestMailboxCode(messages, newTime.Add(time.Minute), "ChatGPT", now)
	if ok {
		t.Fatalf("latestMailboxCode(after future) ok=true, want false")
	}
}

func TestLatestMailboxCodeOnlyUsesFiveMinuteWindow(t *testing.T) {
	now := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	messages := []Message{
		{ID: "too-old", Subject: "ChatGPT code", Body: "code 111111", ReceivedAt: now.Add(-6 * time.Minute)},
		{ID: "older", Subject: "ChatGPT code", Body: "code 222222", ReceivedAt: now.Add(-4 * time.Minute)},
		{ID: "newest", Subject: "ChatGPT code", Body: "code 333333", ReceivedAt: now.Add(-30 * time.Second)},
	}

	msg, code, ok := latestMailboxCode(messages, time.Time{}, "ChatGPT", now)
	if !ok || msg.ID != "newest" || code != "333333" {
		t.Fatalf("latestMailboxCode() msg=%s code=%q ok=%v, want newest 333333 true", msg.ID, code, ok)
	}

	tooOld := Message{ID: "too-old", Subject: "ChatGPT code", Body: "code 111111", ReceivedAt: now.Add(-6 * time.Minute)}
	_, _, ok = latestMailboxCode([]Message{tooOld}, time.Time{}, "ChatGPT", now)
	if ok {
		t.Fatalf("latestMailboxCode(old only) ok=true, want false")
	}
}

func TestLatestMailboxCodeUsesCreatedAtWhenReceivedAtMissing(t *testing.T) {
	now := time.Date(2026, 6, 21, 20, 6, 0, 0, time.UTC)
	messages := []Message{
		{ID: "old", Subject: "ChatGPT code", Body: "code 111111", CreatedAt: time.Date(2026, 6, 21, 20, 0, 0, 0, time.UTC)},
		{ID: "new", Subject: "ChatGPT code", Body: "code 222222", CreatedAt: time.Date(2026, 6, 21, 20, 5, 0, 0, time.UTC)},
	}

	msg, code, ok := latestMailboxCode(messages, time.Time{}, "ChatGPT", now)
	if !ok || msg.ID != "new" || code != "222222" {
		t.Fatalf("latestMailboxCode() msg=%s code=%q ok=%v, want new 222222 true", msg.ID, code, ok)
	}
}

func TestSyncMailboxSerializesPerOwner(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-sync"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID: ownerID,
		DSID:    "123",
		Cookies: []SessionCookie{{Name: "session", Value: "x"}},
	}); err != nil {
		t.Fatal(err)
	}
	first, err := store.AddMailboxForOwner(ownerID, "acc", "first", "first@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddMailboxForOwner(ownerID, "acc", "second", "second@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	started := make(chan string, 2)
	release := make(chan struct{})
	var active int64
	var maxActive int64
	server.syncMailboxMessages = func(ctx context.Context, session ICloudSession, mailbox Mailbox, after time.Time, keyword string, maxThreads int) ([]ICloudSyncedMessage, error) {
		nowActive := atomic.AddInt64(&active, 1)
		for {
			old := atomic.LoadInt64(&maxActive)
			if nowActive <= old || atomic.CompareAndSwapInt64(&maxActive, old, nowActive) {
				break
			}
		}
		started <- mailbox.Email
		select {
		case <-release:
		case <-ctx.Done():
			atomic.AddInt64(&active, -1)
			return nil, ctx.Err()
		}
		atomic.AddInt64(&active, -1)
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	errs := make(chan error, 2)
	go func() {
		_, err := server.syncMailbox(ctx, first, time.Time{}, "ChatGPT")
		errs <- err
	}()
	if got := <-started; got != first.Email {
		t.Fatalf("first started %s, want %s", got, first.Email)
	}
	go func() {
		_, err := server.syncMailbox(ctx, second, time.Time{}, "ChatGPT")
		errs <- err
	}()

	select {
	case got := <-started:
		t.Fatalf("second sync started before first finished: %s", got)
	case <-time.After(50 * time.Millisecond):
	}
	release <- struct{}{}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if got := <-started; got != second.Email {
		t.Fatalf("second started %s, want %s", got, second.Email)
	}
	release <- struct{}{}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&maxActive); got != 1 {
		t.Fatalf("max active sync = %d, want 1", got)
	}
}

func TestMailboxCodeRequestsShareOwnerBatchSync(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-code"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID: ownerID,
		DSID:    "123",
		Cookies: []SessionCookie{{Name: "session", Value: "x"}},
	}); err != nil {
		t.Fatal(err)
	}
	first, err := store.AddMailboxForOwner(ownerID, "acc", "first", "first@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddMailboxForOwner(ownerID, "acc", "second", "second@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var calls int64
	server.syncMailboxBatch = func(ctx context.Context, session ICloudSession, mailboxes []Mailbox, after time.Time, keyword string, maxThreads int) (map[string][]ICloudSyncedMessage, error) {
		atomic.AddInt64(&calls, 1)
		now := time.Now()
		out := make(map[string][]ICloudSyncedMessage, len(mailboxes))
		for _, mailbox := range mailboxes {
			switch mailbox.Email {
			case first.Email:
				out[mailbox.ID] = []ICloudSyncedMessage{{
					RemoteID:   "r1",
					UID:        "1",
					Subject:    "ChatGPT code",
					Body:       "Use 111111 to continue.",
					ReceivedAt: now,
				}}
			case second.Email:
				out[mailbox.ID] = []ICloudSyncedMessage{{
					RemoteID:   "r2",
					UID:        "2",
					Subject:    "ChatGPT code",
					Body:       "Use 222222 to continue.",
					ReceivedAt: now,
				}}
			}
		}
		return out, nil
	}

	type response struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	requestCode := func(mailbox Mailbox) response {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+"&after=2000-01-01T00:00:00Z", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("code request for %s = %d body=%s", mailbox.Email, rr.Code, rr.Body.String())
		}
		var body response
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var firstBody, secondBody response
	go func() {
		defer wg.Done()
		firstBody = requestCode(first)
	}()
	go func() {
		defer wg.Done()
		secondBody = requestCode(second)
	}()
	wg.Wait()

	if !firstBody.Success || firstBody.Code != "111111" {
		t.Fatalf("first body = %+v, want 111111", firstBody)
	}
	if !secondBody.Success || secondBody.Code != "222222" {
		t.Fatalf("second body = %+v, want 222222", secondBody)
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("batch sync calls = %d, want 1", got)
	}
}

func TestLoginProtectsManagementAPI(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status without admin = %d, want 401", rr.Code)
	}

	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status with admin login = %d, want 200", rr.Code)
	}
}

func TestStoreMigratesLegacyMailboxesToSoleOwnerAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now()
	state := State{
		NextID: 10,
		Users: []User{{
			ID:        "usr_1",
			Username:  "owner@example.com",
			Status:    StatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		}},
		Accounts: []Account{{
			ID:           "acc_1",
			OwnerID:      "usr_1",
			Label:        "main",
			AppleID:      "owner@example.com",
			Status:       StatusActive,
			ICloudStatus: ICloudStatusActive,
			CreatedAt:    now,
			UpdatedAt:    now,
		}},
		Mailboxes: []Mailbox{{
			ID:           "mbx_1",
			OwnerID:      "usr_1",
			Label:        "legacy",
			Email:        "alias@icloud.com",
			APIToken:     "token",
			APIActive:    true,
			ICloudActive: true,
			Status:       StatusAvailable,
			CreatedAt:    now,
			UpdatedAt:    now,
		}},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	if got := snapshot.Mailboxes[0].AccountID; got != "acc_1" {
		t.Fatalf("legacy mailbox account_id = %q, want acc_1", got)
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

func TestMailboxSchedulerStartsCreatesAndStops(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "timer-user", "timer123")
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		SavedAt:            time.Now(),
		DSID:               "dsid-1",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
	}); err != nil {
		t.Fatal(err)
	}

	var seq int64
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		select {
		case <-ctx.Done():
			return Mailbox{}, ICloudRemoteMailbox{}, ctx.Err()
		default:
		}
		n := atomic.AddInt64(&seq, 1)
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, fmt.Sprintf("sched-%d@icloud.com", n))
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/start", strings.NewReader(`{"batch_size":2,"interval_seconds":60,"label":"SCH"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("start scheduler = %d body=%s", rr.Code, rr.Body.String())
	}

	var status struct {
		Scheduler publicMailboxScheduler `json:"scheduler"`
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/api/icloud/scheduler/status", nil)
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("scheduler status = %d body=%s", rr.Code, rr.Body.String())
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Scheduler.Success >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status.Scheduler.Success != 2 || len(status.Scheduler.Events) == 0 {
		t.Fatalf("scheduler did not create 2 mailboxes: %+v", status.Scheduler)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/stop", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("stop scheduler = %d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Scheduler.Running {
		t.Fatalf("scheduler still running after stop: %+v", status.Scheduler)
	}
}

func TestSaveICloudSessionForOwnerKeepsMultipleAppleAccounts(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-multi"
	for _, session := range []ICloudSession{
		{OwnerID: ownerID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: ownerID, AppleID: "second@example.com", DSID: "dsid-second", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
			t.Fatal(err)
		}
	}

	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2: %+v", len(sessions), sessions)
	}
	if sessions[0].AccountID == "" || sessions[1].AccountID == "" || sessions[0].AccountID == sessions[1].AccountID {
		t.Fatalf("account ids not separated: %+v", sessions)
	}
	state := store.SnapshotForOwner(ownerID)
	if len(state.Accounts) != 2 {
		t.Fatalf("accounts = %d, want 2: %+v", len(state.Accounts), state.Accounts)
	}
}

func TestCreateICloudMailboxCreatesForEachSavedSession(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "multi-create", "multi123")
	for _, session := range []ICloudSession{
		{OwnerID: user.ID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: user.ID, AppleID: "second@example.com", DSID: "dsid-second", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	wantAccounts := map[string]bool{}
	for _, session := range sessions {
		wantAccounts[session.AccountID] = false
	}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		if ownerID != user.ID {
			t.Fatalf("ownerID = %q, want %q", ownerID, user.ID)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, accountID+"@icloud.com")
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(`{"label":"LAB"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success   bool            `json:"success"`
		Created   int             `json:"created"`
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Created != 2 || len(body.Mailboxes) != 2 {
		t.Fatalf("body = %+v, want two mailboxes", body)
	}
	for _, mailbox := range body.Mailboxes {
		if _, ok := wantAccounts[mailbox.AccountID]; !ok {
			t.Fatalf("unexpected account id %q in mailbox %+v; want %+v", mailbox.AccountID, mailbox, wantAccounts)
		}
		wantAccounts[mailbox.AccountID] = true
	}
	for accountID, seen := range wantAccounts {
		if !seen {
			t.Fatalf("account %s did not create mailbox", accountID)
		}
	}
}

func TestSyncMailboxUsesMailboxAccountSession(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-account-sync"
	for _, session := range []ICloudSession{
		{OwnerID: ownerID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: ownerID, AppleID: "second@example.com", DSID: "dsid-second", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	targetAccountID := sessions[1].AccountID
	mailbox, err := store.AddMailboxForOwner(ownerID, targetAccountID, "target", "target@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncMailboxMessages = func(ctx context.Context, session ICloudSession, mailbox Mailbox, after time.Time, keyword string, maxThreads int) ([]ICloudSyncedMessage, error) {
		if session.AccountID != targetAccountID {
			t.Fatalf("sync used account %q, want %q", session.AccountID, targetAccountID)
		}
		return []ICloudSyncedMessage{{
			RemoteID:   "m1",
			UID:        "1",
			Subject:    "ChatGPT code",
			Body:       "Use 123456 to continue.",
			ReceivedAt: time.Now(),
		}}, nil
	}
	count, err := server.syncMailbox(context.Background(), mailbox, time.Time{}, "ChatGPT")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("synced = %d, want 1", count)
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

func registerTestUser(t *testing.T, handler http.Handler, username, password string) (*http.Cookie, publicUser) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("register user %s = %d body=%s", username, rr.Code, rr.Body.String())
	}
	var body struct {
		User publicUser `json:"user"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			return cookie, body.User
		}
	}
	t.Fatalf("register user %s did not set session cookie", username)
	return nil, publicUser{}
}

func createTestMailboxWithCookie(t *testing.T, handler http.Handler, cookie *http.Cookie, label, email string) publicMailbox {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes", strings.NewReader(`{"label":"`+label+`","email":"`+email+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
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
