package app

import "time"

const (
	StatusActive    = "active"
	StatusAvailable = "available"
	StatusUsed      = "used"
	StatusFailed    = "failed"
	StatusDisabled  = "disabled"

	ICloudStatusActive       = "active"
	ICloudStatusNeedLogin    = "need_login"
	ICloudStatusNeed2FA      = "need_2fa"
	ICloudStatusNoICloudPlus = "no_icloud_plus"
	ICloudStatusRateLimited  = "rate_limited"
	ICloudStatusFailed       = "failed"
)

type State struct {
	NextID        int            `json:"next_id"`
	Accounts      []Account      `json:"accounts"`
	Mailboxes     []Mailbox      `json:"mailboxes"`
	Messages      []Message      `json:"messages"`
	ICloudSession *ICloudSession `json:"icloud_session,omitempty"`
}

type Account struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	AppleID      string    `json:"apple_id"`
	Status       string    `json:"status"`
	ICloudStatus string    `json:"icloud_status"`
	Note         string    `json:"note"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Mailbox struct {
	ID           string    `json:"id"`
	AccountID    string    `json:"account_id"`
	Label        string    `json:"label"`
	Email        string    `json:"email"`
	APIToken     string    `json:"api_token"`
	APIActive    bool      `json:"api_active"`
	ICloudActive bool      `json:"icloud_active"`
	ReceiveCount int       `json:"receive_count"`
	Status       string    `json:"status"`
	Note         string    `json:"note"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Message struct {
	ID         string    `json:"id"`
	MailboxID  string    `json:"mailbox_id"`
	RemoteID   string    `json:"remote_id,omitempty"`
	Source     string    `json:"source,omitempty"`
	Subject    string    `json:"subject"`
	From       string    `json:"from"`
	Body       string    `json:"body"`
	ReceivedAt time.Time `json:"received_at"`
	CreatedAt  time.Time `json:"created_at"`
}

type ICloudSession struct {
	SavedAt            time.Time       `json:"saved_at"`
	AppleID            string          `json:"apple_id,omitempty"`
	DSID               string          `json:"dsid"`
	ClientID           string          `json:"client_id"`
	ClientBuildNumber  string          `json:"client_build_number"`
	MasteringNumber    string          `json:"client_mastering_number"`
	PremiumMailBaseURL string          `json:"premium_mail_base_url"`
	MailGatewayBaseURL string          `json:"mail_gateway_base_url,omitempty"`
	MailBaseURL        string          `json:"mail_base_url,omitempty"`
	Host               string          `json:"host"`
	IsICloudPlus       bool            `json:"is_icloud_plus"`
	CanCreateHME       bool            `json:"can_create_hme"`
	Cookies            []SessionCookie `json:"cookies"`
	Note               string          `json:"note,omitempty"`
	LastCheckedAt      time.Time       `json:"last_checked_at,omitempty"`
	LastCheckOK        bool            `json:"last_check_ok,omitempty"`
	LastStatusMessage  string          `json:"last_status_message,omitempty"`
}

type SessionCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires,omitempty"`
	Secure   bool    `json:"secure,omitempty"`
	HTTPOnly bool    `json:"http_only,omitempty"`
	SameSite string  `json:"same_site,omitempty"`
}

type publicAccount struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	AppleID      string `json:"apple_id"`
	Status       string `json:"status"`
	ICloudStatus string `json:"icloud_status"`
	Note         string `json:"note"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type publicMailbox struct {
	ID           string `json:"id"`
	AccountID    string `json:"account_id"`
	Label        string `json:"label"`
	Email        string `json:"email"`
	APITokenMask string `json:"api_token_mask"`
	APIURL       string `json:"api_url"`
	APIActive    bool   `json:"api_active"`
	ICloudActive bool   `json:"icloud_active"`
	ReceiveCount int    `json:"receive_count"`
	Status       string `json:"status"`
	Note         string `json:"note"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type publicMessage struct {
	ID         string `json:"id"`
	MailboxID  string `json:"mailbox_id"`
	Subject    string `json:"subject"`
	From       string `json:"from"`
	Body       string `json:"body"`
	ReceivedAt string `json:"received_at"`
	CreatedAt  string `json:"created_at"`
}

type publicICloudSession struct {
	Saved              bool   `json:"saved"`
	SavedAt            string `json:"saved_at,omitempty"`
	AppleID            string `json:"apple_id,omitempty"`
	DSIDMask           string `json:"dsid_mask,omitempty"`
	ClientBuildNumber  string `json:"client_build_number,omitempty"`
	MasteringNumber    string `json:"client_mastering_number,omitempty"`
	PremiumMailBaseURL string `json:"premium_mail_base_url,omitempty"`
	MailGatewayBaseURL string `json:"mail_gateway_base_url,omitempty"`
	MailBaseURL        string `json:"mail_base_url,omitempty"`
	Host               string `json:"host,omitempty"`
	IsICloudPlus       bool   `json:"is_icloud_plus"`
	CanCreateHME       bool   `json:"can_create_hme"`
	CookieCount        int    `json:"cookie_count"`
	ProviderConfigured bool   `json:"provider_configured"`
	NeedsManualLogin   bool   `json:"needs_manual_login"`
	LastCheckedAt      string `json:"last_checked_at,omitempty"`
	LastCheckOK        bool   `json:"last_check_ok"`
	LastStatusMessage  string `json:"last_status_message,omitempty"`
}

type apiError struct {
	Success   bool   `json:"success"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}
