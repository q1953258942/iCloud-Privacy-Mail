package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	appleAuthUserAgent        = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15"
	defaultAppleOAuthClientID = "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d"
)

type AppleAuthClient struct {
	httpClient *http.Client
}

type appleAuthEndpoints struct {
	Home  string
	Setup string
	Auth  string
	Host  string
}

type appleAuthSession struct {
	Endpoints      appleAuthEndpoints
	AppleID        string
	ClientID       string
	FrameID        string
	SessionToken   string
	Scnt           string
	SessionID      string
	AccountCountry string
	TrustToken     string
	AuthAttributes string
	Cookies        []SessionCookie
}

type appleSRPInitResponse struct {
	Iteration int    `json:"iteration"`
	Salt      string `json:"salt"`
	Protocol  string `json:"protocol"`
	B         string `json:"b"`
	C         string `json:"c"`
}

type appleAuthStartResult struct {
	Session   ICloudSession
	PendingID string
	Needs2FA  bool
	Message   string
	AppleID   string
	ExpiresAt time.Time
}

type appleDomainRedirectError struct {
	DomainToUse string
	Host        string
}

func (e appleDomainRedirectError) Error() string {
	if e.Host != "" {
		return "Apple 要求切换 iCloud 域：" + e.Host
	}
	return "Apple 要求切换 iCloud 域：" + e.DomainToUse
}

type appleAccountInfo struct {
	DSInfo struct {
		DSID                            string `json:"dsid"`
		AppleID                         string `json:"appleId"`
		PrimaryEmail                    string `json:"primaryEmail"`
		IsHideMyEmailSubscriptionActive bool   `json:"isHideMyEmailSubscriptionActive"`
		IsHideMyEmailFeatureAvailable   bool   `json:"isHideMyEmailFeatureAvailable"`
		HsaVersion                      int    `json:"hsaVersion"`
	} `json:"dsInfo"`
	Webservices map[string]struct {
		URL         string `json:"url"`
		Status      string `json:"status"`
		PcsRequired bool   `json:"pcsRequired"`
	} `json:"webservices"`
	HsaChallengeRequired bool `json:"hsaChallengeRequired"`
}

type appleAuthPending struct {
	ID        string
	Session   *appleAuthSession
	CreatedAt time.Time
	ExpiresAt time.Time
}

type appleAuthPendingStore struct {
	mu    sync.Mutex
	items map[string]appleAuthPending
}

func NewAppleAuthClient() *AppleAuthClient {
	return &AppleAuthClient{httpClient: &http.Client{Timeout: 30 * time.Second}}
}

func newAppleAuthPendingStore() *appleAuthPendingStore {
	return &appleAuthPendingStore{items: make(map[string]appleAuthPending)}
}

func (s *appleAuthPendingStore) put(session *appleAuthSession) (appleAuthPending, error) {
	id, err := randomToken(18)
	if err != nil {
		return appleAuthPending{}, err
	}
	now := time.Now()
	pending := appleAuthPending{
		ID:        id,
		Session:   session,
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	s.items[id] = pending
	return pending, nil
}

func (s *appleAuthPendingStore) get(id string) (appleAuthPending, bool) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	pending, ok := s.items[strings.TrimSpace(id)]
	return pending, ok
}

func (s *appleAuthPendingStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, strings.TrimSpace(id))
}

func (s *appleAuthPendingStore) cleanupLocked(now time.Time) {
	for id, pending := range s.items {
		if now.After(pending.ExpiresAt) {
			delete(s.items, id)
		}
	}
}

func (c *AppleAuthClient) StartLogin(ctx context.Context, appleID, password, defaultHost, clientID string, pendingStore *appleAuthPendingStore) (appleAuthStartResult, error) {
	appleID = strings.ToLower(strings.TrimSpace(appleID))
	if appleID == "" || strings.TrimSpace(password) == "" {
		return appleAuthStartResult{}, errCode("apple_credentials_missing", "缺少 Apple ID 或密码", false)
	}
	result, err := c.startLoginOnHost(ctx, appleID, password, defaultHost, clientID, pendingStore)
	if err == nil {
		return result, nil
	}
	var redirect appleDomainRedirectError
	if !errors.As(err, &redirect) || redirect.Host == "" {
		return appleAuthStartResult{}, err
	}
	currentHost := appleAuthEndpointsForHost(defaultHost).Host
	nextHost := appleAuthEndpointsForHost(redirect.Host).Host
	if currentHost == nextHost {
		return appleAuthStartResult{}, err
	}
	return c.startLoginOnHost(ctx, appleID, password, nextHost, clientID, pendingStore)
}

func (c *AppleAuthClient) startLoginOnHost(ctx context.Context, appleID, password, host, clientID string, pendingStore *appleAuthPendingStore) (appleAuthStartResult, error) {
	frameID, err := randomUUID()
	if err != nil {
		return appleAuthStartResult{}, err
	}
	session := &appleAuthSession{
		Endpoints: appleAuthEndpointsForHost(host),
		AppleID:   appleID,
		ClientID:  firstNonEmpty(clientID, defaultAppleOAuthClientID),
		FrameID:   strings.ToLower(frameID),
	}
	if err := c.authStart(ctx, session); err != nil {
		return appleAuthStartResult{}, err
	}
	if err := c.authFederate(ctx, session); err != nil {
		return appleAuthStartResult{}, err
	}
	needs2FA, err := c.authSRP(ctx, session, password)
	if err != nil {
		return appleAuthStartResult{}, err
	}
	if session.SessionToken == "" {
		return appleAuthStartResult{}, errCode("apple_session_token_missing", "Apple 登录未返回 Session Token，请重新协议登录或检查账号安全状态", true)
	}
	if needs2FA {
		message := "已触发 Apple 2FA，请在受信任设备允许后输入 6 位验证码"
		if err := c.requestTrustedDeviceCode(ctx, session); err != nil {
			var redirect appleDomainRedirectError
			if errors.As(err, &redirect) {
				return appleAuthStartResult{}, err
			}
			message = "Apple 已要求 2FA；自动触发验证码未确认，请查看受信任设备后输入验证码"
		}
		pending, err := pendingStore.put(session)
		if err != nil {
			return appleAuthStartResult{}, err
		}
		return appleAuthStartResult{
			PendingID: pending.ID,
			Needs2FA:  true,
			Message:   message,
			AppleID:   maskAppleID(appleID),
			ExpiresAt: pending.ExpiresAt,
		}, nil
	}

	icloudSession, err := c.authWithTokenAndValidate(ctx, session)
	if err != nil {
		var redirect appleDomainRedirectError
		if errors.As(err, &redirect) {
			return appleAuthStartResult{}, err
		}
		pending, putErr := pendingStore.put(session)
		if putErr != nil {
			return appleAuthStartResult{}, putErr
		}
		return appleAuthStartResult{
			PendingID: pending.ID,
			Needs2FA:  true,
			Message:   "登录已进入二次验证；如果设备已弹码，请输入验证码继续",
			AppleID:   maskAppleID(appleID),
			ExpiresAt: pending.ExpiresAt,
		}, nil
	}
	return appleAuthStartResult{
		Session:  icloudSession,
		Needs2FA: false,
		Message:  "Apple 协议登录成功，登录态已生成",
		AppleID:  maskAppleID(appleID),
	}, nil
}

func (c *AppleAuthClient) Submit2FA(ctx context.Context, pending appleAuthPending, code string) (ICloudSession, error) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return ICloudSession{}, errCode("invalid_2fa_code", "2FA 验证码必须是 6 位", false)
	}
	session := pending.Session
	for attempt := 0; attempt < 2; attempt++ {
		icloudSession, err := c.submit2FAWithSession(ctx, session, code)
		if err == nil {
			return icloudSession, nil
		}
		var redirect appleDomainRedirectError
		if !errors.As(err, &redirect) || !session.switchHost(redirect.Host) {
			return ICloudSession{}, err
		}
	}
	return ICloudSession{}, errCode("apple_domain_switch_failed", "Apple 登录域切换后仍未完成 2FA，请重新发起协议登录", true)
}

func (c *AppleAuthClient) submit2FAWithSession(ctx context.Context, session *appleAuthSession, code string) (ICloudSession, error) {
	if err := c.validateTrustedDeviceCode(ctx, session, code); err != nil {
		return ICloudSession{}, err
	}
	if err := c.trustSession(ctx, session); err != nil {
		return ICloudSession{}, err
	}
	return c.authWithTokenAndValidate(ctx, session)
}

func appleAuthEndpointsForHost(host string) appleAuthEndpoints {
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.Contains(host, "icloud.com.cn") {
		return appleAuthEndpoints{
			Home:  "https://www.icloud.com.cn",
			Setup: "https://setup.icloud.com.cn/setup/ws/1",
			Auth:  "https://idmsa.apple.com.cn/appleauth/auth",
			Host:  "www.icloud.com.cn",
		}
	}
	return appleAuthEndpoints{
		Home:  "https://www.icloud.com",
		Setup: "https://setup.icloud.com/setup/ws/1",
		Auth:  "https://idmsa.apple.com/appleauth/auth",
		Host:  "www.icloud.com",
	}
}

func appleDomainToHost(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimSuffix(domain, "/")
	if strings.Contains(domain, "icloud.com.cn") {
		return "www.icloud.com.cn"
	}
	if strings.Contains(domain, "icloud.com") {
		return "www.icloud.com"
	}
	return ""
}

func parseAppleDomainRedirect(status int, data []byte) (appleDomainRedirectError, bool) {
	if status < 300 || status >= 400 {
		return appleDomainRedirectError{}, false
	}
	var payload struct {
		DomainToUse string `json:"domainToUse"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(data), &payload); err != nil {
		return appleDomainRedirectError{}, false
	}
	host := appleDomainToHost(payload.DomainToUse)
	if host == "" {
		return appleDomainRedirectError{}, false
	}
	return appleDomainRedirectError{DomainToUse: payload.DomainToUse, Host: host}, true
}

func (c *AppleAuthClient) authStart(ctx context.Context, session *appleAuthSession) error {
	frameTag := "auth-" + session.FrameID
	u, err := url.Parse(session.Endpoints.Auth + "/authorize/signin")
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("frame_id", frameTag)
	q.Set("language", "zh_CN")
	q.Set("skVersion", "7")
	q.Set("iframeId", frameTag)
	q.Set("client_id", session.ClientID)
	q.Set("redirect_uri", session.Endpoints.Home)
	q.Set("response_type", "code")
	q.Set("response_mode", "web_message")
	q.Set("state", frameTag)
	q.Set("authVersion", "latest")
	u.RawQuery = q.Encode()
	_, _, err = c.do(ctx, session, http.MethodGet, u.String(), map[string]string{"Accept": "*/*"}, nil, nil, false)
	return err
}

func (c *AppleAuthClient) authFederate(ctx context.Context, session *appleAuthSession) error {
	u := session.Endpoints.Auth + "/federate?isRememberMeEnabled=true"
	body := map[string]any{"accountName": session.AppleID, "rememberMe": true}
	_, _, err := c.do(ctx, session, http.MethodPost, u, session.srpHeaders(), body, nil, false)
	return err
}

func (c *AppleAuthClient) authSRP(ctx context.Context, session *appleAuthSession, password string) (bool, error) {
	srp, err := newSRPClient()
	if err != nil {
		return false, err
	}
	var initResp appleSRPInitResponse
	initBody := map[string]any{
		"a":           base64.StdEncoding.EncodeToString(srp.ABytes()),
		"accountName": session.AppleID,
		"protocols":   []string{"s2k", "s2k_fo"},
	}
	if _, _, err := c.do(ctx, session, http.MethodPost, session.Endpoints.Auth+"/signin/init", session.srpHeaders(), initBody, &initResp, false); err != nil {
		return false, err
	}
	serverB, err := base64.StdEncoding.DecodeString(initResp.B)
	if err != nil {
		return false, fmt.Errorf("decode SRP B: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(initResp.Salt)
	if err != nil {
		return false, fmt.Errorf("decode SRP salt: %w", err)
	}
	derived, err := deriveAppleSRPPassword(password, salt, initResp.Iteration, initResp.Protocol)
	if err != nil {
		return false, err
	}
	if err := srp.processChallenge([]byte(session.AppleID), derived, salt, serverB); err != nil {
		return false, err
	}
	completeBody := map[string]any{
		"accountName": session.AppleID,
		"m1":          base64.StdEncoding.EncodeToString(srp.M1),
		"m2":          base64.StdEncoding.EncodeToString(srp.M2),
		"c":           initResp.C,
		"rememberMe":  true,
		"trustTokens": []string{},
	}
	if session.TrustToken != "" {
		completeBody["trustTokens"] = []string{session.TrustToken}
	}
	status, _, err := c.do(ctx, session, http.MethodPost, session.Endpoints.Auth+"/signin/complete?isRememberMeEnabled=true", session.srpHeaders(), completeBody, nil, true)
	return status == http.StatusConflict, err
}

func (c *AppleAuthClient) requestTrustedDeviceCode(ctx context.Context, session *appleAuthSession) error {
	_, _, err := c.do(ctx, session, http.MethodGet, session.Endpoints.Auth+"/verify/trusteddevice", session.authHeaders(), nil, nil, false)
	return err
}

func (c *AppleAuthClient) validateTrustedDeviceCode(ctx context.Context, session *appleAuthSession, code string) error {
	body := map[string]any{"securityCode": map[string]string{"code": code}}
	_, _, err := c.do(ctx, session, http.MethodPost, session.Endpoints.Auth+"/verify/trusteddevice/securitycode", session.authHeaders(), body, nil, false)
	if err != nil {
		var redirect appleDomainRedirectError
		if errors.As(err, &redirect) {
			return err
		}
		return errCode("apple_2fa_failed", "Apple 2FA 验证失败："+err.Error(), true)
	}
	return nil
}

func (c *AppleAuthClient) trustSession(ctx context.Context, session *appleAuthSession) error {
	_, _, err := c.do(ctx, session, http.MethodGet, session.Endpoints.Auth+"/2sv/trust", session.authHeaders(), nil, nil, false)
	return err
}

func (c *AppleAuthClient) authWithTokenAndValidate(ctx context.Context, session *appleAuthSession) (ICloudSession, error) {
	if session.SessionToken == "" {
		return ICloudSession{}, errCode("apple_session_token_missing", "Apple Session Token 缺失，无法换取 iCloud 登录态", true)
	}
	var account appleAccountInfo
	body := map[string]any{
		"accountCountryCode": session.AccountCountry,
		"dsWebAuthToken":     session.SessionToken,
		"extended_login":     true,
		"trustToken":         session.TrustToken,
	}
	headers := session.commonHeaders(map[string]string{})
	if _, _, err := c.do(ctx, session, http.MethodPost, session.Endpoints.Setup+"/accountLogin", headers, body, &account, false); err != nil {
		return ICloudSession{}, err
	}
	cookies := session.cloneCookies()
	validate, err := NewICloudSessionValidator().Validate(ctx, cookies, session.Endpoints.Host)
	if err != nil {
		return ICloudSession{}, err
	}
	return ICloudSession{
		SavedAt:            time.Now(),
		AppleID:            firstNonEmpty(validate.AppleID, account.DSInfo.AppleID, account.DSInfo.PrimaryEmail, session.AppleID),
		DSID:               validate.DSID,
		ClientID:           validate.ClientID,
		ClientBuildNumber:  validate.ClientBuildNumber,
		MasteringNumber:    validate.MasteringNumber,
		PremiumMailBaseURL: strings.TrimRight(validate.PremiumMailBaseURL, "/"),
		MailGatewayBaseURL: strings.TrimRight(validate.MailGatewayBaseURL, "/"),
		MailBaseURL:        strings.TrimRight(validate.MailBaseURL, "/"),
		Host:               session.Endpoints.Host,
		IsICloudPlus:       validate.IsICloudPlus,
		CanCreateHME:       validate.CanCreateHME,
		Cookies:            cookies,
		Note:               "saved from Go Apple SRP protocol login",
	}, nil
}

func (c *AppleAuthClient) do(ctx context.Context, session *appleAuthSession, method, rawURL string, headers map[string]string, body any, out any, allow409 bool) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", appleAuthUserAgent)
	for key, value := range headers {
		if strings.TrimSpace(value) != "" {
			req.Header.Set(key, value)
		}
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie := cookieHeader(session.Cookies, rawURL); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	session.extract(resp)
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if redirect, ok := parseAppleDomainRedirect(resp.StatusCode, data); ok {
		return resp.StatusCode, data, redirect
	}
	if resp.StatusCode == http.StatusForbidden {
		return resp.StatusCode, nil, errCode("apple_login_forbidden", "Apple ID 或密码错误，或当前账号被限制登录", true)
	}
	if allow409 && resp.StatusCode == http.StatusConflict {
		return resp.StatusCode, data, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, nil, errCode("apple_protocol_http_error", fmt.Sprintf("Apple 协议 HTTP %d: %s", resp.StatusCode, trimForError(data)), true)
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, nil, errCode("apple_protocol_bad_json", "Apple 协议返回无法解析", true)
		}
	}
	return resp.StatusCode, data, nil
}

func (s *appleAuthSession) extract(resp *http.Response) {
	s.mergeCookies(resp.Request.URL, resp.Cookies())
	if v := resp.Header.Get("X-Apple-ID-Account-Country"); v != "" {
		s.AccountCountry = v
	}
	if v := resp.Header.Get("X-Apple-ID-Session-Id"); v != "" {
		s.SessionID = v
	}
	if v := resp.Header.Get("X-Apple-Session-Token"); v != "" {
		s.SessionToken = v
	}
	if v := resp.Header.Get("X-Apple-TwoSV-Trust-Token"); v != "" {
		s.TrustToken = v
	}
	if v := resp.Header.Get("scnt"); v != "" {
		s.Scnt = v
	}
	if v := resp.Header.Get("X-Apple-Auth-Attributes"); v != "" {
		s.AuthAttributes = v
	}
}

func (s *appleAuthSession) switchHost(host string) bool {
	next := appleAuthEndpointsForHost(host)
	if next.Host == "" || next.Host == s.Endpoints.Host {
		return false
	}
	s.Endpoints = next
	return true
}

func (s *appleAuthSession) mergeCookies(requestURL *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		domain := strings.TrimSpace(c.Domain)
		if domain == "" && requestURL != nil {
			domain = requestURL.Hostname()
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		next := SessionCookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   domain,
			Path:     path,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
		}
		if !c.Expires.IsZero() {
			next.Expires = float64(c.Expires.Unix())
		}
		replaced := false
		for i, old := range s.Cookies {
			if old.Name == next.Name && strings.EqualFold(strings.TrimPrefix(old.Domain, "."), strings.TrimPrefix(next.Domain, ".")) && old.Path == next.Path {
				if next.Value == "" {
					s.Cookies = append(s.Cookies[:i], s.Cookies[i+1:]...)
				} else {
					s.Cookies[i] = next
				}
				replaced = true
				break
			}
		}
		if !replaced && next.Value != "" {
			s.Cookies = append(s.Cookies, next)
		}
	}
}

func (s *appleAuthSession) cloneCookies() []SessionCookie {
	return append([]SessionCookie(nil), s.Cookies...)
}

func (s *appleAuthSession) srpHeaders() map[string]string {
	frameTag := "auth-" + s.FrameID
	origin := strings.TrimSuffix(s.Endpoints.Auth, "/appleauth/auth")
	headers := map[string]string{
		"Accept":                           "application/json",
		"Content-Type":                     "application/json",
		"Origin":                           origin,
		"Referer":                          origin + "/",
		"X-Apple-Widget-Key":               s.ClientID,
		"X-Apple-OAuth-Client-Id":          s.ClientID,
		"X-Apple-OAuth-Client-Type":        "firstPartyAuth",
		"X-Apple-OAuth-Redirect-URI":       s.Endpoints.Home,
		"X-Apple-OAuth-Require-Grant-Code": "true",
		"X-Apple-OAuth-Response-Mode":      "web_message",
		"X-Apple-OAuth-Response-Type":      "code",
		"X-Apple-OAuth-State":              frameTag,
		"X-Apple-Frame-Id":                 frameTag,
		"X-Requested-With":                 "XMLHttpRequest",
		"X-Apple-Mandate-Security-Upgrade": "0",
		"X-Apple-I-Require-UE":             "true",
		"X-Apple-I-FD-Client-Info":         `{"U":"` + appleAuthUserAgent + `","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":""}`,
	}
	if s.AuthAttributes != "" {
		headers["X-Apple-Auth-Attributes"] = s.AuthAttributes
	}
	if s.Scnt != "" {
		headers["scnt"] = s.Scnt
	}
	if s.SessionID != "" {
		headers["X-Apple-ID-Session-Id"] = s.SessionID
	}
	if s.SessionToken != "" {
		headers["X-Apple-Session-Token"] = s.SessionToken
	}
	return headers
}

func (s *appleAuthSession) authHeaders() map[string]string {
	return s.srpHeaders()
}

func (s *appleAuthSession) commonHeaders(overwrite map[string]string) map[string]string {
	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"Origin":       s.Endpoints.Home,
		"Referer":      s.Endpoints.Home + "/",
		"User-Agent":   appleAuthUserAgent,
	}
	for key, value := range overwrite {
		headers[key] = value
	}
	return headers
}
