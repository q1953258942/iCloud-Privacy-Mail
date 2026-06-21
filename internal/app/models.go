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
	NextID    int       `json:"next_id"`
	Accounts  []Account `json:"accounts"`
	Mailboxes []Mailbox `json:"mailboxes"`
	Messages  []Message `json:"messages"`
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
	Subject    string    `json:"subject"`
	From       string    `json:"from"`
	Body       string    `json:"body"`
	ReceivedAt time.Time `json:"received_at"`
	CreatedAt  time.Time `json:"created_at"`
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

type apiError struct {
	Success   bool   `json:"success"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}
