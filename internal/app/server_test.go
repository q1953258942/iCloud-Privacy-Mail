package app

import (
	"context"
	"crypto/sha1"
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

func TestGenerateAppleHashcash(t *testing.T) {
	challenge := "0123456789abcdef0123456789abcdef"
	now := time.Date(2026, 6, 29, 14, 2, 22, 0, time.UTC)
	got, err := generateAppleHashcash(8, challenge, now)
	if err != nil {
		t.Fatalf("generateAppleHashcash() error = %v", err)
	}
	parts := strings.Split(got, ":")
	if len(parts) != 6 {
		t.Fatalf("hashcash parts = %d, want 6 in %q", len(parts), got)
	}
	if parts[0] != "1" || parts[1] != "8" || parts[2] != "20260629140222" || parts[3] != challenge || parts[4] != "" || parts[5] == "" {
		t.Fatalf("hashcash format mismatch: %q", got)
	}
	sum := sha1.Sum([]byte(got))
	if leadingZeroBits(sum[:]) < 8 {
		t.Fatalf("hashcash does not satisfy requested difficulty")
	}
}

func TestAppleAccountFDClientInfoUsesBrowserFingerprint(t *testing.T) {
	var info map[string]string
	if err := json.Unmarshal([]byte(appleAccountFDClientInfo(appleAccountManageUserAgent)), &info); err != nil {
		t.Fatal(err)
	}
	if info["U"] != appleAccountManageUserAgent {
		t.Fatalf("U = %q, want manage user agent", info["U"])
	}
	if info["L"] != appleAccountManageLanguage || info["Z"] != appleAccountManageGMTOffset || info["V"] != "1.1" {
		t.Fatalf("unexpected locale fields: %+v", info)
	}
	if len(info["F"]) < 80 {
		t.Fatalf("F length = %d, want browser fingerprint", len(info["F"]))
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

func TestAppleDebugBodyRedactsSecrets(t *testing.T) {
	got := appleDebugBody([]byte(`{"apiKey":"secret-api","emailAddress":"alias@example.com","nested":{"sessionToken":"secret-token","forwardToEmail":"main@example.com"},"ok":true}`))
	if strings.Contains(got, "secret-api") || strings.Contains(got, "secret-token") || strings.Contains(got, "alias@example.com") || strings.Contains(got, "main@example.com") {
		t.Fatalf("debug body leaked secret: %s", got)
	}
	if !strings.Contains(got, "<redacted>") || !strings.Contains(got, `"ok":true`) {
		t.Fatalf("debug body = %s, want redacted secret and visible safe fields", got)
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

func TestICloudClientMoveRemoteMessagesToTrashAndEmptyTrash(t *testing.T) {
	var sawMove bool
	var sawDestroy bool
	client := &ICloudClient{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		response := `{}`
		switch r.URL.Path {
		case "/mailws2/v1/geqs/query":
			response = `{"domainObjects":[{"identifier":"31","name":"INBOX","messageCount":1},{"identifier":"53","name":"Deleted Messages","messageCount":1}]}`
		case "/mailws2/v1/message/list":
			if strings.Contains(string(body), `"value":"31"`) {
				response = `{"domainObjects":[{"uid":7,"identifier":"msg-inbox","mboxRef":{"id":"31"}}]}`
			} else if strings.Contains(string(body), `"value":"53"`) {
				response = `{"domainObjects":[{"uid":7,"identifier":"msg-trash","mboxRef":{"id":"53"}}]}`
			}
		case "/mailws2/v1/email/set":
			if strings.Contains(string(body), `"batchUpdate"`) {
				sawMove = true
				response = `{"updated":{"msg-inbox":{"modseq":4}}}`
			} else if strings.Contains(string(body), `"destroy"`) {
				sawDestroy = true
				response = `{"destroyed":["msg-trash"]}`
			}
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(response)),
			Request:    r,
		}, nil
	})}}
	session := ICloudSession{
		MailGatewayBaseURL: "https://p39-mccgateway.icloud.com",
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
	}
	moved, err := client.MoveRemoteMessagesToTrash(t.Context(), session, []string{"icloud:INBOX:7", "local:bad"})
	if err != nil {
		t.Fatal(err)
	}
	if moved.MovedToTrash != 1 || moved.Skipped != 1 || !sawMove {
		t.Fatalf("moved = %+v sawMove=%v, want moved=1 skipped=1", moved, sawMove)
	}
	destroyed, err := client.EmptyTrash(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	if destroyed != 1 || !sawDestroy {
		t.Fatalf("destroyed=%d sawDestroy=%v, want 1", destroyed, sawDestroy)
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

func TestPublicSessionSeparatesLoginStateKinds(t *testing.T) {
	appleOnly := publicSession(&ICloudSession{
		SavedAt: time.Now(),
		AppleID: "apple@example.com",
		DSID:    "123456",
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Scnt:   "scnt",
			APIKey: "api-key",
		}},
	})
	if !appleOnly.AppleAccountLoginSaved || !appleOnly.AppleAccountManageReady {
		t.Fatalf("apple account state not exposed: %+v", appleOnly)
	}
	if appleOnly.ICloudWebLoginSaved || appleOnly.NeedsManualLogin {
		t.Fatalf("apple-only state mixed with iCloud web: %+v", appleOnly)
	}

	icloudOnly := publicSession(&ICloudSession{
		SavedAt:      time.Now(),
		AppleID:      "icloud@example.com",
		DSID:         "654321",
		IsICloudPlus: true,
		CanCreateHME: true,
		Cookies:      []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
	})
	if !icloudOnly.ICloudWebLoginSaved || !icloudOnly.ProviderConfigured {
		t.Fatalf("icloud web state not exposed: %+v", icloudOnly)
	}
	if icloudOnly.AppleAccountLoginSaved || icloudOnly.AppleAccountManageReady {
		t.Fatalf("icloud-only state mixed with apple account: %+v", icloudOnly)
	}
}

func TestPublicSessionExposesPerLoginStateCheckStatus(t *testing.T) {
	checkedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	got := publicSession(&ICloudSession{
		SavedAt: time.Now(),
		AppleID: "state@example.com",
		LoginStates: []LoginState{
			{
				Kind:              LoginStateAppleAccount,
				Scnt:              "scnt",
				APIKey:            "api-key",
				LastCheckedAt:     checkedAt,
				LastCheckOK:       true,
				LastStatusMessage: "新接口登录态正常",
			},
			{
				Kind:              LoginStateICloudWeb,
				Cookies:           []SessionCookie{{Name: "icloud", Value: "ok"}},
				LastCheckedAt:     checkedAt,
				LastCheckOK:       false,
				LastStatusMessage: "旧接口登录态异常",
			},
		},
	})
	if !got.AppleAccountLoginChecked || !got.AppleAccountLoginOK || got.AppleAccountLoginStatus != "登录态正常" {
		t.Fatalf("apple account status = checked:%t ok:%t text:%q", got.AppleAccountLoginChecked, got.AppleAccountLoginOK, got.AppleAccountLoginStatus)
	}
	if !got.ICloudWebLoginChecked || got.ICloudWebLoginOK || got.ICloudWebLoginStatus != "登录态异常" {
		t.Fatalf("icloud web status = checked:%t ok:%t text:%q", got.ICloudWebLoginChecked, got.ICloudWebLoginOK, got.ICloudWebLoginStatus)
	}
}

func TestPublicViewsExposeFullAppleID(t *testing.T) {
	store := newTestStore(t)
	server := &Server{cfg: Config{PublicBaseURL: "https://mail.example"}, store: store, logger: discardLogger()}
	account, err := store.AddAccountForOwner("owner-full", "Main", "full.user@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner("owner-full", account.ID, "Alias", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	gotAccount := server.publicAccount(account)
	if gotAccount.AppleID != "full.user@example.com" {
		t.Fatalf("public account AppleID = %q, want full email", gotAccount.AppleID)
	}

	gotMailbox := server.publicMailbox(httptest.NewRequest(http.MethodGet, "https://panel.example/", nil), mailbox)
	if gotMailbox.AccountAppleID != "full.user@example.com" {
		t.Fatalf("public mailbox account AppleID = %q, want full email", gotMailbox.AccountAppleID)
	}

	gotSession := publicSession(&ICloudSession{
		SavedAt:   time.Now(),
		AccountID: account.ID,
		AppleID:   "session.user@example.com",
	})
	if gotSession.AppleID != "session.user@example.com" {
		t.Fatalf("public session AppleID = %q, want full email", gotSession.AppleID)
	}

	matched := publicSessionForAppleID([]publicICloudSession{gotSession}, "session.user@example.com")
	if matched.AppleID != gotSession.AppleID {
		t.Fatalf("publicSessionForAppleID did not match full email: %+v", matched)
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

func TestICloudClientCreatePrivacyMailboxWithAppleAccount(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Apple-I-Request-Context") != "ca" {
			t.Fatalf("request context = %q, want ca", r.Header.Get("X-Apple-I-Request-Context"))
		}
		if r.Header.Get("Origin") != "https://account.apple.com" {
			t.Fatalf("origin = %q, want account.apple.com", r.Header.Get("Origin"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			tokenCalls++
			if tokenCalls != 1 {
				t.Fatalf("unexpected token call %d", tokenCalls)
			}
			if r.Header.Get("X-Apple-Api-Key") != "" {
				t.Fatalf("token api key header = %q, want empty", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-token" {
				t.Fatalf("token scnt header = %q, want scnt-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			http.SetCookie(w, &http.Cookie{Name: "token-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("X-Apple-Api-Key") != "" {
				t.Fatalf("manage api key header = %q, want empty", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "token-cookie=ok") {
				t.Fatalf("manage cookie header = %q, want token response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("add api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			body, _ := io.ReadAll(r.Body)
			if strings.TrimSpace(string(body)) != "{}" {
				t.Fatalf("add body = %s, want {}", body)
			}
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","newToPrivateEmail":false,"exists":false,"type":"settings","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("complete api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-add" {
				t.Fatalf("complete scnt header = %q, want scnt-after-add", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-complete")
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["emailAddress"] != "Candidate.Alias@icloud.com" || body["label"] != "LAB" || body["note"] != "note" {
				t.Fatalf("complete body = %+v", body)
			}
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","label":"LAB","note":"note","id":"abc123","type":"settings","active":false}`))
		case "GET /account/manage/email/private/abc123.em":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("confirm api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-complete" {
				t.Fatalf("confirm scnt header = %q, want scnt-after-complete", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-confirm")
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","label":"LAB","note":"note","id":"abc123","forwardToEmail":"main@example.com","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Scnt:   "scnt-token",
			APIKey: "stale-key",
		}},
	}, "", "LAB", "note")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "candidate.alias@icloud.com" || remote.Label != "LAB" || remote.AnonymousID != "abc123" || !remote.IsActive || remote.ForwardToEmail != "main@example.com" || remote.Origin != "APPLE_ACCOUNT" {
		t.Fatalf("remote = %+v", remote)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/abc123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.Scnt != "scnt-after-confirm" || updatedState.APIKey != "account-key" {
		t.Fatalf("updated apple account state = %+v ok=%v, want refreshed scnt/api key", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountReusesFreshState(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token", "GET /account/manage":
			t.Fatalf("unexpected refresh request %s %s", r.Method, r.URL.Path)
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("add api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-current" {
				t.Fatalf("add scnt header = %q, want scnt-current", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"Fresh.Alias@icloud.com","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("complete api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-add" {
				t.Fatalf("complete scnt header = %q, want scnt-after-add", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-complete")
			_, _ = w.Write([]byte(`{"emailAddress":"Fresh.Alias@icloud.com","id":"fresh123","active":true}`))
		case "GET /account/manage/email/private/fresh123.em":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("confirm api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-complete" {
				t.Fatalf("confirm scnt header = %q, want scnt-after-complete", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-confirm")
			_, _ = w.Write([]byte(`{"emailAddress":"Fresh.Alias@icloud.com","id":"fresh123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	checkedAt := time.Now()
	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:          LoginStateAppleAccount,
			Scnt:          "scnt-current",
			APIKey:        "fresh-key",
			LastCheckedAt: checkedAt,
			LastCheckOK:   true,
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "fresh.alias@icloud.com" {
		t.Fatalf("remote email = %q, want fresh.alias@icloud.com", remote.Email)
	}
	wantPaths := []string{
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/fresh123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.Scnt != "scnt-after-confirm" || updatedState.APIKey != "fresh-key" || !updatedState.LastCheckOK || updatedState.LastCheckedAt.IsZero() || updatedState.LastCheckedAt.Before(checkedAt) {
		t.Fatalf("updated apple account state = %+v ok=%v, want reused fresh state marked ok", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRefreshesAfterAuthFailure(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	addCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			addCalls++
			if addCalls == 1 {
				if r.Header.Get("X-Apple-Api-Key") != "old-key" {
					t.Fatalf("first add api key header = %q, want old-key", r.Header.Get("X-Apple-Api-Key"))
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"service_errors":[{"message":"expired"}]}`))
				return
			}
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("retry add api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("retry add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"Retry.Alias@icloud.com","active":false}`))
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("X-Apple-Api-Key") != "" {
				t.Fatalf("token api key header = %q, want empty", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-old" {
				t.Fatalf("token scnt header = %q, want scnt-old", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "PUT /account/manage/email/private/add/complete":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("complete api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			_, _ = w.Write([]byte(`{"emailAddress":"Retry.Alias@icloud.com","id":"retry123","active":true}`))
		case "GET /account/manage/email/private/retry123.em":
			_, _ = w.Write([]byte(`{"emailAddress":"Retry.Alias@icloud.com","id":"retry123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:          LoginStateAppleAccount,
			Scnt:          "scnt-old",
			APIKey:        "old-key",
			LastCheckedAt: time.Now(),
			LastCheckOK:   true,
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "retry.alias@icloud.com" {
		t.Fatalf("remote email = %q, want retry.alias@icloud.com", remote.Email)
	}
	wantPaths := []string{
		"POST /account/manage/email/private/add",
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/retry123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.APIKey != "account-key" || updatedState.Scnt != "scnt-after-add" || !updatedState.LastCheckOK {
		t.Fatalf("updated apple account state = %+v ok=%v, want refreshed state", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRequiresManageSession(t *testing.T) {
	client := NewICloudClient()
	_, _, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{}, "account-key", "LAB", "")
	coded, ok := err.(codedError)
	if !ok {
		t.Fatalf("error type = %T, want codedError", err)
	}
	if coded.code != "apple_account_session_missing" {
		t.Fatalf("code = %q, want apple_account_session_missing", coded.code)
	}
}

func TestCheckSavedLoginStatesChecksAppleAccountState(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "scnt-token" {
				t.Fatalf("token scnt header = %q, want scnt-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	checkedAt := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	client := &ICloudClient{client: ts.Client()}
	session, ok, err := checkSavedLoginStates(context.Background(), client, ICloudSession{
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Origin: appleAccountManageOrigin,
			Scnt:   "scnt-token",
		}},
	}, checkedAt)
	if err != nil || !ok {
		t.Fatalf("checkSavedLoginStates err=%v ok=%t", err, ok)
	}
	state, found := appleAccountLoginState(session)
	if !found {
		t.Fatalf("apple account state missing: %+v", session.LoginStates)
	}
	if state.APIKey != "account-key" || state.Scnt != "scnt-after-manage" || !state.LastCheckOK || !state.LastCheckedAt.Equal(checkedAt) || state.LastStatusMessage != "新接口登录态正常" {
		t.Fatalf("updated state = %+v", state)
	}
	if !session.LastCheckOK || !strings.Contains(session.LastStatusMessage, "新接口正常") {
		t.Fatalf("session check status = ok:%t message:%q", session.LastCheckOK, session.LastStatusMessage)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestAppleAuthClientPrimeAppleAccountManageStateKeepsChallengeScnt(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/section/privacy":
			w.Header().Set("scnt", "page-scnt")
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "" {
				t.Fatalf("pre-login token scnt header = %q, want empty", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "manage-scnt")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	session := &appleAuthSession{
		Endpoints: appleAccountManageAuthEndpoints(),
		UserAgent: appleAccountManageUserAgent,
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.primeAppleAccountManageState(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if session.ManageScnt != "manage-scnt" {
		t.Fatalf("ManageScnt = %q, want manage-scnt", session.ManageScnt)
	}
	wantPaths := []string{
		"GET /account/manage/section/privacy",
		"GET /bootstrap/portal",
		"GET /account/manage/gs/ws/token",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestAppleAuthClientAuthStartPreservesAppleAccountCompleteHashcashChallenge(t *testing.T) {
	var gotPath string
	var gotAuthVersion string
	var gotSecFetchDest string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthVersion = r.URL.Query().Get("authVersion")
		gotSecFetchDest = r.Header.Get("Sec-Fetch-Dest")
		if r.Header.Get("Accept") == "" || !strings.Contains(r.Header.Get("Accept"), "text/html") {
			t.Fatalf("Accept = %q, want browser navigation accept", r.Header.Get("Accept"))
		}
		w.Header().Set("X-Apple-HC-Bits", "8")
		w.Header().Set("X-Apple-HC-Challenge", "initial-challenge")
		_, _ = w.Write([]byte(`<html></html>`))
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		ClientID:  appleAccountManageOAuthClientID,
		FrameID:   "unit",
		UserAgent: appleAccountManageUserAgent,
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.authStart(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/authorize/signin" {
		t.Fatalf("path = %q, want /authorize/signin", gotPath)
	}
	if gotAuthVersion != "8.0.2" {
		t.Fatalf("authVersion = %q, want 8.0.2", gotAuthVersion)
	}
	if gotSecFetchDest != "iframe" {
		t.Fatalf("Sec-Fetch-Dest = %q, want iframe", gotSecFetchDest)
	}
	if session.CompleteHCBits != 8 || session.CompleteHCChallenge != "initial-challenge" {
		t.Fatalf("complete hashcash = %d/%q, want 8/initial-challenge", session.CompleteHCBits, session.CompleteHCChallenge)
	}

	session.HCBits = 12
	session.HCChallenge = "later-challenge"
	bits, challenge := session.completeHashcashChallenge()
	if bits != 8 || challenge != "initial-challenge" {
		t.Fatalf("completeHashcashChallenge() = %d/%q, want preserved initial challenge", bits, challenge)
	}
}

func TestAppleAuthClientAuthFederateEnablesRememberMeForAppleAccountManage(t *testing.T) {
	var body map[string]any
	var rememberQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/federate" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		rememberQuery = r.URL.Query().Get("isRememberMeEnabled")
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		AppleID:   "user@example.com",
		ClientID:  appleAccountManageOAuthClientID,
		UserAgent: appleAccountManageUserAgent,
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.authFederate(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if rememberQuery != "true" {
		t.Fatalf("isRememberMeEnabled = %q, want true", rememberQuery)
	}
	if body["rememberMe"] != true {
		t.Fatalf("rememberMe = %#v, want true", body["rememberMe"])
	}
	if body["accountName"] != "user@example.com" {
		t.Fatalf("accountName = %#v, want user@example.com", body["accountName"])
	}
}

func TestAppleAuthClientAuthSRPUsesPreservedAppleAccountHashcashAndBrowserBody(t *testing.T) {
	var completeHashcash string
	var completeBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /signin/init":
			w.Header().Set("X-Apple-HC-Bits", "12")
			w.Header().Set("X-Apple-HC-Challenge", "later-challenge")
			_, _ = w.Write([]byte(`{"iteration":1,"salt":"c2FsdA==","protocol":"s2k","b":"Ag==","c":"proof-context"}`))
		case "POST /signin/complete":
			completeHashcash = r.Header.Get("X-Apple-HC")
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &completeBody); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		AppleID:        "user@example.com",
		ClientID:       appleAccountManageOAuthClientID,
		HCBits:         8,
		HCChallenge:    "initial-challenge",
		UserAgent:      appleAccountManageUserAgent,
		Scnt:           "scnt",
		SessionID:      "session-id",
		AuthAttributes: "attributes",
	}
	session.rememberCompleteHashcashChallenge()

	client := &AppleAuthClient{httpClient: ts.Client()}
	needs2FA, err := client.authSRP(t.Context(), session, "password")
	if err != nil {
		t.Fatal(err)
	}
	if !needs2FA {
		t.Fatalf("needs2FA = false, want true")
	}
	if !strings.Contains(completeHashcash, ":8:") || !strings.Contains(completeHashcash, ":initial-challenge::") {
		t.Fatalf("X-Apple-HC = %q, want preserved initial challenge", completeHashcash)
	}
	if completeBody["rememberMe"] != true {
		t.Fatalf("rememberMe = %#v, want true", completeBody["rememberMe"])
	}
	if _, ok := completeBody["trustTokens"]; ok {
		t.Fatalf("trustTokens present in Apple Account manage complete body: %#v", completeBody["trustTokens"])
	}
	if completeBody["accountName"] != "user@example.com" {
		t.Fatalf("accountName = %#v, want user@example.com", completeBody["accountName"])
	}
}

func TestAppleAccountFallbackPhoneNumber(t *testing.T) {
	if got := string(appleAccountFallbackPhoneNumber(nil)); got != `{"id":1,"nonFTEU":true}` {
		t.Fatalf("nil fallback = %s", got)
	}
	if got := string(appleAccountFallbackPhoneNumber(json.RawMessage(`null`))); got != `{"id":1,"nonFTEU":true}` {
		t.Fatalf("null fallback = %s", got)
	}
	if got := string(appleAccountFallbackPhoneNumber(nil, json.RawMessage(`{"id":3}`))); got != `{"id":3}` {
		t.Fatalf("stored fallback = %s", got)
	}
	if got := string(appleAccountFallbackPhoneNumber(json.RawMessage(`{"id":2}`))); got != `{"id":2}` {
		t.Fatalf("explicit phone = %s", got)
	}
}

func TestAppleAuthClientRequestsBrowser2FACodeEndpoints(t *testing.T) {
	var paths []string
	var phoneBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "PUT /verify/trusteddevice/securitycode":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{}`))
		case "PUT /verify/phone":
			if err := json.NewDecoder(r.Body).Decode(&phoneBody); err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		ClientID:       appleAccountManageOAuthClientID,
		FrameID:        "unit",
		UserAgent:      appleAccountManageUserAgent,
		Scnt:           "scnt-token",
		SessionID:      "session-id",
		TwoFactorPhone: json.RawMessage(`{"id":2,"nonFTEU":true}`),
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.requestTrustedDeviceCode(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if err := client.requestPhoneSecurityCode(t.Context(), session, nil); err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"PUT /verify/trusteddevice/securitycode",
		"PUT /verify/phone",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	phone, ok := phoneBody["phoneNumber"].(map[string]any)
	if !ok {
		t.Fatalf("phoneNumber = %#v, want object", phoneBody["phoneNumber"])
	}
	if phone["id"] != float64(2) {
		t.Fatalf("phone id = %#v, want 2", phone["id"])
	}
	if _, ok := phone["nonFTEU"]; ok {
		t.Fatalf("send phoneNumber should not include nonFTEU: %#v", phone)
	}
	if phoneBody["mode"] != "sms" {
		t.Fatalf("mode = %#v, want sms", phoneBody["mode"])
	}
}

func TestSubmitAppleAccountManage2FADefaultsTrustedDeviceAndUsesFreshScnt(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var authPaths []string
	var submittedCode string
	authTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authPaths = append(authPaths, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "POST /verify/trusteddevice/securitycode":
			var body struct {
				SecurityCode struct {
					Code string `json:"code"`
				} `json:"securityCode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			submittedCode = body.SecurityCode.Code
			w.Header().Set("scnt", "fresh-scnt")
			w.Header().Set("X-Apple-ID-Session-Id", "fresh-session")
			w.WriteHeader(http.StatusNoContent)
		case "GET /2sv/trust":
			if r.Header.Get("scnt") != "fresh-scnt" {
				t.Fatalf("trust scnt header = %q, want fresh-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "trusted-scnt")
			w.Header().Set("X-Apple-ID-Session-Id", "trusted-session")
			http.SetCookie(w, &http.Cookie{Name: "trust-cookie", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer authTS.Close()

	var managePaths []string
	tokenCalls := 0
	manageTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		managePaths = append(managePaths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			tokenCalls++
			if tokenCalls != 1 {
				t.Fatalf("unexpected token call %d", tokenCalls)
			}
			if r.Header.Get("scnt") != "trusted-scnt" {
				t.Fatalf("token scnt header = %q, want trusted-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "token-scnt")
			http.SetCookie(w, &http.Cookie{Name: "manage-token", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "token-scnt" {
				t.Fatalf("manage scnt header = %q, want token-scnt", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "manage-token=ok") {
				t.Fatalf("manage cookie header = %q, want token response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		default:
			t.Fatalf("unexpected manage request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer manageTS.Close()
	appleAccountManageBaseURL = manageTS.URL

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: authTS.URL,
			Host: "appleid.apple.com",
		},
		AppleID:    "user@example.com",
		ClientID:   appleAccountManageOAuthClientID,
		FrameID:    "unit",
		UserAgent:  appleAccountManageUserAgent,
		Scnt:       "old-scnt",
		ManageScnt: "stale-manage-scnt",
		SessionID:  "old-session",
	}
	client := &AppleAuthClient{httpClient: authTS.Client()}
	icloudSession, err := client.SubmitAppleAccountManage2FA(t.Context(), appleAuthPending{Session: session}, "123456", nil)
	if err != nil {
		t.Fatal(err)
	}
	if submittedCode != "123456" {
		t.Fatalf("submitted code = %q, want 123456", submittedCode)
	}
	wantAuthPaths := []string{
		"POST /verify/trusteddevice/securitycode",
		"GET /2sv/trust",
	}
	if strings.Join(authPaths, "\n") != strings.Join(wantAuthPaths, "\n") {
		t.Fatalf("auth paths = %#v, want %#v", authPaths, wantAuthPaths)
	}
	wantManagePaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
	}
	if strings.Join(managePaths, "\n") != strings.Join(wantManagePaths, "\n") {
		t.Fatalf("manage paths = %#v, want %#v", managePaths, wantManagePaths)
	}
	state, ok := appleAccountLoginState(icloudSession)
	if !ok || state.Scnt != "manage-scnt" || state.APIKey != "account-key" || state.SessionID != "trusted-session" {
		t.Fatalf("apple account state = %+v ok=%v, want fresh session/scnt/api key", state, ok)
	}
	if !strings.Contains(cookieHeader(state.Cookies, authTS.URL+"/2sv/trust"), "trust-cookie=ok") {
		t.Fatalf("apple account state cookies = %+v, want trust cookie saved", state.Cookies)
	}
}

func TestAppleAuthClientValidatePhoneCodeUsesStoredPhoneNumber(t *testing.T) {
	var body map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/verify/phone/securitycode" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		ClientID:       appleAccountManageOAuthClientID,
		FrameID:        "unit",
		UserAgent:      appleAccountManageUserAgent,
		TwoFactorPhone: json.RawMessage(`{"id":4,"nonFTEU":true}`),
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.validatePhoneSecurityCode(t.Context(), session, "123456", nil); err != nil {
		t.Fatal(err)
	}
	phone, ok := body["phoneNumber"].(map[string]any)
	if !ok {
		t.Fatalf("phoneNumber = %#v, want object", body["phoneNumber"])
	}
	if phone["id"] != float64(4) || phone["nonFTEU"] != true {
		t.Fatalf("phoneNumber = %#v, want stored id and nonFTEU", phone)
	}
	securityCode := body["securityCode"].(map[string]any)
	if securityCode["code"] != "123456" || body["mode"] != "sms" {
		t.Fatalf("body = %#v, want code and sms mode", body)
	}
}

func TestAppleAuthSessionRememberTwoFactorPhoneNumberFromAuthHTML(t *testing.T) {
	session := &appleAuthSession{}
	session.rememberTwoFactorPhoneNumber([]byte(`<html><script id="app_config" type="application/json">{"bootData":{"twoSV":{"trustedDeviceVerification":{"phoneNumberVerification":{"trustedPhoneNumbers":[{"id":7,"numberWithDialCode":"+1 ***"}]}}}}}</script></html>`))
	if string(session.TwoFactorPhone) != `{"id":7}` {
		t.Fatalf("TwoFactorPhone = %s, want id 7", session.TwoFactorPhone)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRefreshesAPIKey(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			tokenCalls++
			if tokenCalls != 1 {
				t.Fatalf("unexpected token call %d", tokenCalls)
			}
			if r.Header.Get("scnt") != "scnt-token" {
				t.Fatalf("token scnt header = %q, want scnt-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			http.SetCookie(w, &http.Cookie{Name: "token-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "token-cookie=ok") {
				t.Fatalf("manage cookie header = %q, want token response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			http.SetCookie(w, &http.Cookie{Name: "manage-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "manage-cookie=ok") {
				t.Fatalf("add cookie header = %q, want manage response cookie", r.Header.Get("Cookie"))
			}
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","id":"abc123","active":true}`))
		case "GET /account/manage/email/private/abc123.em":
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","id":"abc123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	_, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind: LoginStateAppleAccount,
			Scnt: "scnt-token",
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.APIKey != "account-key" {
		t.Fatalf("updated apple account state = %+v ok=%v, want api key", updatedState, ok)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/abc123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
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

func TestAdminCanDeleteNormalUserAndOwnedData(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())

	adminCookie, adminUser := registerTestUser(t, handler, "admin", "admin123")
	userCookie, normalUser := registerTestUser(t, handler, "alice", "alice123")
	account, err := store.AddAccountForOwner(normalUser.ID, "Alice Apple", "alice@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(normalUser.ID, ICloudSession{
		OwnerID: normalUser.ID,
		AppleID: "alice@example.com",
		DSID:    "alice-dsid",
		Cookies: []SessionCookie{{Name: "session", Value: "secret"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(normalUser.ID, account.ID, "ALICE", "alice-alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "Your OpenAI code is 123456", "noreply@example.com", "123456", time.Now()); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+normalUser.ID, nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin delete user = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Deleted DeleteUserResult `json:"deleted"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Deleted.UserID != normalUser.ID || body.Deleted.Accounts != 1 || body.Deleted.Mailboxes != 1 || body.Deleted.Messages != 1 || body.Deleted.ICloudSessions != 1 || body.Deleted.WebSessions == 0 {
		t.Fatalf("deleted result = %+v", body.Deleted)
	}

	state := store.Snapshot()
	if len(state.Users) != 1 || state.Users[0].ID != adminUser.ID {
		t.Fatalf("users after delete = %+v", state.Users)
	}
	if len(state.Accounts) != 0 || len(state.Mailboxes) != 0 || len(state.Messages) != 0 || len(state.ICloudSessions) != 0 {
		t.Fatalf("owned data after delete accounts=%d mailboxes=%d messages=%d sessions=%d", len(state.Accounts), len(state.Mailboxes), len(state.Messages), len(state.ICloudSessions))
	}
	for _, session := range state.WebSessions {
		if session.UserID == normalUser.ID {
			t.Fatalf("deleted user session still present: %+v", session)
		}
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("deleted user manage data = %d body=%s, want 401", rr.Code, rr.Body.String())
	}
}

func TestAdminDeleteUserRejectsSelfAndAdminAccounts(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())

	adminCookie, adminUser := registerTestUser(t, handler, "admin", "admin123")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+adminUser.ID, nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "cannot_delete_self") {
		t.Fatalf("admin self delete = %d body=%s", rr.Code, rr.Body.String())
	}

	secondAdmin, err := store.CreateUser("second-admin", "admin123")
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	for i := range store.state.Users {
		if store.state.Users[i].ID == secondAdmin.ID {
			store.state.Users[i].IsAdmin = true
		}
	}
	if err := store.saveLocked(); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+secondAdmin.ID, nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "cannot_delete_admin_user") {
		t.Fatalf("delete other admin = %d body=%s", rr.Code, rr.Body.String())
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

func TestMailboxCodeQuerySyncsBeforeReturningCachedOldCode(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-fresh"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID: ownerID,
		DSID:    "123",
		Cookies: []SessionCookie{{Name: "session", Value: "x"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 111111 to continue.", time.Now().Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var calls int64
	server.syncMailboxBatch = func(ctx context.Context, session ICloudSession, mailboxes []Mailbox, after time.Time, keyword string, maxThreads int) (map[string][]ICloudSyncedMessage, error) {
		atomic.AddInt64(&calls, 1)
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "remote-new",
				UID:        "2",
				Subject:    "ChatGPT code",
				Body:       "Use 222222 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken, nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success   bool   `json:"success"`
		Code      string `json:"code"`
		MessageID string `json:"message_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "222222" {
		t.Fatalf("code body = %+v, want fresh 222222", body)
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("sync calls = %d, want 1", got)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing")
	}
	if updated.LastCodeMessageID == "" || updated.LastCodeMessageID != body.MessageID {
		t.Fatalf("LastCodeMessageID=%q response message_id=%q", updated.LastCodeMessageID, body.MessageID)
	}
}

func TestMailboxCodeQueryDoesNotRepeatServedCachedCode(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-repeat"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID: ownerID,
		DSID:    "123",
		Cookies: []SessionCookie{{Name: "session", Value: "x"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 135790 to continue.", time.Now().Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncMailboxBatch = func(ctx context.Context, session ICloudSession, mailboxes []Mailbox, after time.Time, keyword string, maxThreads int) (map[string][]ICloudSyncedMessage, error) {
		return map[string][]ICloudSyncedMessage{}, nil
	}

	requestCode := func(query string) struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
		Error   string `json:"error"`
	} {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+query, nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("code request %q = %d body=%s", query, rr.Code, rr.Body.String())
		}
		var body struct {
			Success bool   `json:"success"`
			Code    string `json:"code"`
			Error   string `json:"error"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	first := requestCode("")
	if !first.Success || first.Code != "135790" {
		t.Fatalf("first code = %+v, want 135790", first)
	}
	second := requestCode("")
	if second.Success || second.Code != "no_code" {
		t.Fatalf("second code = %+v, want no_code without repeating cached OTP", second)
	}
	cached := requestCode("&cache=1")
	if !cached.Success || cached.Code != "135790" {
		t.Fatalf("cache code = %+v, want cached 135790", cached)
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

func TestLookupMailboxesRequiresGlobalAPIKeyAndKeepsStatus(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{APIKey: "global-key", PublicBaseURL: "https://mail.example"}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/lookup", strings.NewReader(`{"emails":["alias@icloud.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("lookup without key = %d, want 401", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/lookup", strings.NewReader(`{"emails":["ALIAS@icloud.com","missing@icloud.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer global-key")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("lookup with key = %d, body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success   bool            `json:"success"`
		Mailboxes []publicMailbox `json:"mailboxes"`
		Missing   []string        `json:"missing"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || len(body.Mailboxes) != 1 || body.Mailboxes[0].ID != mailbox.ID {
		t.Fatalf("lookup body = %+v", body)
	}
	if len(body.Missing) != 1 || body.Missing[0] != "missing@icloud.com" {
		t.Fatalf("missing = %+v", body.Missing)
	}
	if !strings.HasPrefix(body.Mailboxes[0].APIURL, "https://mail.example/") {
		t.Fatalf("api_url = %q", body.Mailboxes[0].APIURL)
	}
	updated, ok := store.FindMailboxByEmail("alias@icloud.com")
	if !ok || updated.Status != StatusAvailable {
		t.Fatalf("lookup changed mailbox status: %+v ok=%v", updated, ok)
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
		if n > 2 {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "当前小时额度已用完", true)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, fmt.Sprintf("sched-%d@icloud.com", n))
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/start", strings.NewReader(`{"batch_size":200,"interval_seconds":60,"label":"SCH"}`))
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
		if status.Scheduler.Success >= 2 && status.Scheduler.Failed >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status.Scheduler.BatchSize != 1 {
		t.Fatalf("scheduler batch size = %d, want hidden request batch_size ignored as 1", status.Scheduler.BatchSize)
	}
	if status.Scheduler.Success != 2 || status.Scheduler.Failed != 1 || len(status.Scheduler.Events) == 0 {
		t.Fatalf("scheduler did not create until account failed: %+v", status.Scheduler)
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

func TestMailboxSchedulerClearLogsKeepsCounters(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "timer-clear", "timer123")

	job := &mailboxSchedulerJob{
		nextEventID: 2,
		state: mailboxSchedulerState{
			OwnerID:         user.ID,
			Owner:           user.Username,
			BatchSize:       1,
			IntervalSeconds: int(time.Hour.Seconds()),
			Status:          "running",
			Success:         3,
			Failed:          1,
		},
		events: []mailboxSchedulerEvent{
			{ID: 2, At: time.Now(), Type: "failed", Message: "失败记录", Batch: 1, Error: "额度已用完"},
			{ID: 1, At: time.Now(), Type: "created", Message: "创建成功", Batch: 1, Email: "created@icloud.com"},
		},
	}
	server.schedulerMu.Lock()
	server.mailboxSchedulers[user.ID] = job
	server.schedulerMu.Unlock()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/logs/clear", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("clear scheduler logs = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Scheduler publicMailboxScheduler `json:"scheduler"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Scheduler.Events) != 0 {
		t.Fatalf("scheduler events after clear = %+v, want empty", body.Scheduler.Events)
	}
	if body.Scheduler.Success != 3 || body.Scheduler.Failed != 1 {
		t.Fatalf("scheduler counters changed after clear: %+v", body.Scheduler)
	}
}

func TestMailboxSchedulerRunsUntilAllAccountsFailWithOnlyInterval(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "timer-until-fail", "timer123")
	for _, session := range []ICloudSession{
		{
			OwnerID:            user.ID,
			AppleID:            "limit@example.com",
			DSID:               "dsid-limit",
			PremiumMailBaseURL: "https://example.invalid",
			IsICloudPlus:       true,
			CanCreateHME:       true,
			Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie-1", Domain: ".icloud.com", Path: "/"}},
		},
		{
			OwnerID:            user.ID,
			AppleID:            "worker@example.com",
			DSID:               "dsid-worker",
			PremiumMailBaseURL: "https://example.invalid",
			IsICloudPlus:       true,
			CanCreateHME:       true,
			Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie-2", Domain: ".icloud.com", Path: "/"}},
		},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	limitAccountID := sessions[0].AccountID
	workerAccountID := sessions[1].AccountID
	accountIDs := []string{limitAccountID, workerAccountID}

	var mu sync.Mutex
	attempts := map[string]int{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		select {
		case <-ctx.Done():
			return Mailbox{}, ICloudRemoteMailbox{}, ctx.Err()
		default:
		}
		mu.Lock()
		attempts[accountID]++
		n := attempts[accountID]
		mu.Unlock()
		if accountID == limitAccountID {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "第一个账号额度已用完", true)
		}
		if n > 2 {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "第二个账号额度已用完", true)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, fmt.Sprintf("%s-%d@icloud.com", accountID, n))
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	body := fmt.Sprintf(`{"account_ids":["%s","%s"],"interval_seconds":60,"label":"SCH"}`, accountIDs[0], accountIDs[1])
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("start scheduler = %d body=%s", rr.Code, rr.Body.String())
	}
	defer func() {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/stop", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
	}()

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
		if status.Scheduler.Success >= 2 && status.Scheduler.Failed >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status.Scheduler.BatchSize != 1 {
		t.Fatalf("scheduler batch size = %d, want 1", status.Scheduler.BatchSize)
	}
	if status.Scheduler.Success != 2 || status.Scheduler.Failed != 2 {
		t.Fatalf("scheduler state = success %d failed %d, want success=2 failed=2: %+v", status.Scheduler.Success, status.Scheduler.Failed, status.Scheduler)
	}
	mu.Lock()
	if attempts[limitAccountID] != 1 {
		mu.Unlock()
		t.Fatalf("limited account attempts = %d, want 1; attempts=%+v", attempts[limitAccountID], attempts)
	}
	if attempts[workerAccountID] != 3 {
		mu.Unlock()
		t.Fatalf("worker account attempts = %d, want 3; attempts=%+v", attempts[workerAccountID], attempts)
	}
	mu.Unlock()
}

func TestMailboxSchedulerSkipsFailedAccountWithinCurrentBatch(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-scheduler-skip"
	for _, session := range []ICloudSession{
		{OwnerID: ownerID, AppleID: "bad@example.com", DSID: "dsid-bad", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: ownerID, AppleID: "good@example.com", DSID: "dsid-good", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	badAccountID := sessions[0].AccountID
	goodAccountID := sessions[1].AccountID
	var attemptsMu sync.Mutex
	attempts := map[string]int{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		attemptsMu.Lock()
		attempts[accountID]++
		attempt := attempts[accountID]
		attemptsMu.Unlock()
		if accountID == badAccountID {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "当前小时额度已用完", true)
		}
		if attempt > 3 {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "好账号本轮也已用完", true)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, fmt.Sprintf("good-%d@icloud.com", attempt))
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, mailboxSchedulerConfig{
		AccountIDs: []string{badAccountID, goodAccountID},
		Label:      "SCH",
		BatchSize:  1,
	}, 1)
	state, events := job.snapshot()
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	if attempts[badAccountID] != 1 {
		t.Fatalf("bad account attempts = %d, want 1; attempts=%+v", attempts[badAccountID], attempts)
	}
	if attempts[goodAccountID] != 4 {
		t.Fatalf("good account attempts = %d, want 4; attempts=%+v", attempts[goodAccountID], attempts)
	}
	if state.Success != 3 || state.Failed != 2 {
		t.Fatalf("scheduler state = %+v, want success=3 failed=2", state)
	}
	if len(events) != 6 {
		t.Fatalf("events = %d, want 6: %+v", len(events), events)
	}
}

func TestMailboxSchedulerFallsBackToOldInterfaceAfterNewInterfaceFails(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-scheduler-fallback"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AppleID:            "fallback@example.com",
		DSID:               "dsid-fallback",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
		LoginStates: []LoginState{
			{Kind: LoginStateAppleAccount, Host: "appleid.apple.com", Origin: "https://account.apple.com", Scnt: "scnt", SessionID: "sid"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	accountID := sessions[0].AccountID

	var attemptsMu sync.Mutex
	attempts := map[mailboxCreateChannel]int{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		channel := mailboxCreateChannelFromContext(ctx)
		attemptsMu.Lock()
		attempts[channel]++
		attempt := attempts[channel]
		attemptsMu.Unlock()
		switch channel {
		case mailboxCreateChannelAppleAccount:
			if attempt > 2 {
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("apple_account_limit", "新接口当前小时额度已用完", true)
			}
		case mailboxCreateChannelICloudWeb:
			if attempt > 1 {
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "旧接口当前小时额度已用完", true)
			}
		default:
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("unexpected_channel", "定时创建没有指定接口", false)
		}
		email := fmt.Sprintf("%s-%d@icloud.com", channel, attempt)
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, email)
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true, Origin: string(channel)}, nil
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, mailboxSchedulerConfig{
		AccountIDs: []string{accountID},
		Label:      "SCH",
		BatchSize:  1,
	}, 1)
	state, events := job.snapshot()
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	if attempts[mailboxCreateChannelAppleAccount] != 3 {
		t.Fatalf("new interface attempts = %d, want 3; attempts=%+v", attempts[mailboxCreateChannelAppleAccount], attempts)
	}
	if attempts[mailboxCreateChannelICloudWeb] != 2 {
		t.Fatalf("old interface attempts = %d, want 2; attempts=%+v", attempts[mailboxCreateChannelICloudWeb], attempts)
	}
	if state.Success != 3 || state.Failed != 1 {
		t.Fatalf("scheduler state = %+v, want success=3 failed=1", state)
	}
	var sawSwitch, sawNewCreated, sawOldCreated, sawOldFailed, sawAccountLabel bool
	for _, event := range events {
		if event.Type == "channel_failed" && strings.Contains(event.Message, "切换旧接口继续尝试") {
			sawSwitch = true
		}
		if event.Type == "created" && strings.Contains(event.Message, "新接口创建成功") {
			sawNewCreated = true
		}
		if event.Type == "created" && strings.Contains(event.Message, "旧接口创建成功") {
			sawOldCreated = true
		}
		if event.Type == "failed" && strings.Contains(event.Message, "旧接口创建失败") {
			sawOldFailed = true
		}
		if strings.Contains(event.Message, "fallback@example.com") {
			sawAccountLabel = true
		}
	}
	if !sawSwitch {
		t.Fatalf("events did not include old-interface fallback: %+v", events)
	}
	if !sawNewCreated || !sawOldCreated || !sawOldFailed {
		t.Fatalf("events did not include create channel labels: newCreated=%v oldCreated=%v oldFailed=%v events=%+v", sawNewCreated, sawOldCreated, sawOldFailed, events)
	}
	if !sawAccountLabel {
		t.Fatalf("events did not include login account label: %+v", events)
	}
}

func TestCreateAppleAccountMailboxSavesRefreshedStateWhenCreateFails(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-apple-refresh-fail"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID: ownerID,
		AppleID: "refresh-fail@example.com",
		LoginStates: []LoginState{{
			Kind:      LoginStateAppleAccount,
			Host:      "appleid.apple.com",
			Origin:    "https://account.apple.com",
			Scnt:      "stale-scnt",
			SessionID: "sid",
			APIKey:    "stale-key",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	session := sessions[0]

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "stale-scnt" {
				t.Fatalf("token scnt header = %q, want stale-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "fresh-token-scnt")
			http.SetCookie(w, &http.Cookie{Name: "token-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "fresh-token-scnt" {
				t.Fatalf("manage scnt header = %q, want fresh-token-scnt", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "token-cookie=ok") {
				t.Fatalf("manage cookie header = %q, want token response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "fresh-manage-scnt")
			http.SetCookie(w, &http.Cookie{Name: "manage-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("add api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "fresh-manage-scnt" {
				t.Fatalf("add scnt header = %q, want fresh-manage-scnt", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "manage-cookie=ok") {
				t.Fatalf("add cookie header = %q, want refreshed cookies", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "fresh-failed-scnt")
			http.SetCookie(w, &http.Cookie{Name: "fail-cookie", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`You have reached the limit of addresses you can create right now. Please try again later.`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	_, err := server.createICloudMailboxRemoteAppleAccount(context.Background(), ownerID, session, "LAB", "", ownerID+":"+session.AccountID)
	if err == nil {
		t.Fatal("create error = nil, want Apple Account limit error")
	}
	got := store.ICloudSessionsForOwner(ownerID)[0]
	state, ok := appleAccountLoginState(got)
	if !ok || state.Scnt != "fresh-failed-scnt" || state.APIKey != "fresh-key" {
		t.Fatalf("saved apple account state = %+v ok=%v, want refreshed state after failed create", state, ok)
	}
	if cookie := cookieHeader(state.Cookies, ts.URL+"/account/manage/email/private/add"); !strings.Contains(cookie, "fail-cookie=ok") {
		t.Fatalf("saved cookie header = %q, want failed response cookie saved", cookie)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
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

func TestSaveICloudSessionForOwnerMergesLoginStates(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-merge"
	icloudSession := ICloudSession{
		OwnerID:            ownerID,
		AppleID:            "same@example.com",
		DSID:               "dsid-same",
		ClientID:           "client",
		PremiumMailBaseURL: "https://p-maildomainws.icloud.com",
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "icloud", Value: "ok", Domain: ".icloud.com", Path: "/"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Host:    "www.icloud.com",
			Cookies: []SessionCookie{{Name: "icloud", Value: "ok", Domain: ".icloud.com", Path: "/"}},
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, icloudSession); err != nil {
		t.Fatal(err)
	}
	appleAccountSession := ICloudSession{
		OwnerID: ownerID,
		AppleID: "same@example.com",
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Host:   "appleid.apple.com",
			Scnt:   "scnt",
			APIKey: "api-key",
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, appleAccountSession); err != nil {
		t.Fatal(err)
	}

	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1: %+v", len(sessions), sessions)
	}
	got := sessions[0]
	if got.DSID != icloudSession.DSID || got.PremiumMailBaseURL != icloudSession.PremiumMailBaseURL || len(got.Cookies) != 1 {
		t.Fatalf("iCloud state was not preserved: %+v", got)
	}
	if _, ok := appleAccountLoginState(got); !ok {
		t.Fatalf("apple account login state missing after merge: %+v", got.LoginStates)
	}
	if !hasLoginStateKind(got.LoginStates, LoginStateICloudWeb) {
		t.Fatalf("iCloud login state missing after merge: %+v", got.LoginStates)
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

func TestCreateICloudMailboxUsesSelectedSavedSessions(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "selected-create", "multi123")
	for _, session := range []ICloudSession{
		{OwnerID: user.ID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: user.ID, AppleID: "broken@example.com", DSID: "dsid-broken", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
		{OwnerID: user.ID, AppleID: "third@example.com", DSID: "dsid-third", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "c", Value: "3"}}},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	selected := []string{sessions[0].AccountID, sessions[2].AccountID}
	var createdMu sync.Mutex
	createdAccounts := map[string]bool{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		if accountID == sessions[1].AccountID {
			t.Fatalf("broken account %q should not be used", accountID)
		}
		createdMu.Lock()
		createdAccounts[accountID] = true
		createdMu.Unlock()
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, accountID+"@icloud.com")
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	bodyJSON := fmt.Sprintf(`{"label":"SEL","account_ids":["%s","%s"]}`, selected[0], selected[1])
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Created   int             `json:"created"`
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Created != 2 || len(body.Mailboxes) != 2 {
		t.Fatalf("body = %+v, want two selected mailboxes", body)
	}
	createdMu.Lock()
	defer createdMu.Unlock()
	for _, accountID := range selected {
		if !createdAccounts[accountID] {
			t.Fatalf("selected account %q was not used; created=%+v", accountID, createdAccounts)
		}
	}
	if createdAccounts[sessions[1].AccountID] {
		t.Fatalf("unselected account %q was used", sessions[1].AccountID)
	}
}

func TestCreateICloudMailboxReturnsAccountFailuresWhenAllSelectedSessionsFail(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "all-fail-create", "multi123")
	for _, session := range []ICloudSession{
		{OwnerID: user.ID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: user.ID, AppleID: "second@example.com", DSID: "dsid-second", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "当前小时额度已用完", true)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(`{"label":"FAIL"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success  bool                   `json:"success"`
		Created  int                    `json:"created"`
		Failures []createMailboxFailure `json:"failures"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Created != 0 || len(body.Failures) != 2 {
		t.Fatalf("body = %+v, want two account failures", body)
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
