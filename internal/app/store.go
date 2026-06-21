package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type FileStore struct {
	mu    sync.Mutex
	path  string
	state State
}

func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		path = filepath.Join("data", "state.json")
	}
	s := &FileStore{path: path, state: State{NextID: 1}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s.saveLocked()
		}
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return s.saveLocked()
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return err
	}
	if s.state.NextID <= 0 {
		s.state.NextID = 1
	}
	return nil
}

func (s *FileStore) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.state)
}

func (s *FileStore) SnapshotForBrowser(browserKey string) State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return filterStateByBrowserKeyLocked(s.state, strings.TrimSpace(browserKey))
}

func (s *FileStore) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

func (s *FileStore) SetPath(path string) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path = strings.TrimSpace(path)
	if path == "" {
		path = filepath.Join("data", "state.json")
	}
	if strings.EqualFold(filepath.Ext(path), ".json") {
		path = filepath.Clean(path)
	} else {
		path = filepath.Join(path, "state.json")
	}
	current := cloneState(s.state)
	data, err := os.ReadFile(path)
	switch {
	case err == nil && len(strings.TrimSpace(string(data))) > 0:
		var next State
		if err := json.Unmarshal(data, &next); err != nil {
			return State{}, err
		}
		if next.NextID <= 0 {
			next.NextID = 1
		}
		s.state = next
	case err == nil:
		s.state = current
	case errors.Is(err, os.ErrNotExist):
		s.state = current
	default:
		return State{}, err
	}
	s.path = path
	if err := s.saveLocked(); err != nil {
		return State{}, err
	}
	return cloneState(s.state), nil
}

func (s *FileStore) EnsureBrowserClient(label, currentKey string, rotate bool) (BrowserClient, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	label = strings.TrimSpace(label)
	currentKey = strings.TrimSpace(currentKey)
	if !rotate && currentKey != "" {
		for i, client := range s.state.BrowserClients {
			if constantTimeEqual(currentKey, client.Key) {
				if label != "" {
					s.state.BrowserClients[i].Label = label
				}
				s.state.BrowserClients[i].LastSeenAt = now
				return s.state.BrowserClients[i], false, s.saveLocked()
			}
		}
	}
	key, err := randomToken(24)
	if err != nil {
		return BrowserClient{}, false, err
	}
	client := BrowserClient{
		Key:        key,
		Label:      label,
		CreatedAt:  now,
		LastSeenAt: now,
	}
	if client.Label == "" {
		client.Label = "浏览器-" + now.Format("0102-150405")
	}
	s.state.BrowserClients = append(s.state.BrowserClients, client)
	return client, true, s.saveLocked()
}

func (s *FileStore) HasBrowserKey(browserKey string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	browserKey = strings.TrimSpace(browserKey)
	if browserKey == "" {
		return false
	}
	for _, client := range s.state.BrowserClients {
		if constantTimeEqual(browserKey, client.Key) {
			return true
		}
	}
	return false
}

func (s *FileStore) AddAccount(label, appleID, note string) (Account, error) {
	return s.AddAccountForBrowser("", label, appleID, note)
}

func (s *FileStore) AddAccountForBrowser(browserKey, label, appleID, note string) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	account := Account{
		ID:           s.nextIDLocked("acc"),
		BrowserKey:   strings.TrimSpace(browserKey),
		Label:        strings.TrimSpace(label),
		AppleID:      strings.TrimSpace(appleID),
		Status:       StatusActive,
		ICloudStatus: ICloudStatusNeedLogin,
		Note:         strings.TrimSpace(note),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if account.Label == "" {
		account.Label = account.ID
	}
	s.state.Accounts = append(s.state.Accounts, account)
	return account, s.saveLocked()
}

func (s *FileStore) AddMailbox(accountID, label, email string) (Mailbox, error) {
	return s.AddMailboxForBrowser("", accountID, label, email)
}

func (s *FileStore) AddMailboxForBrowser(browserKey, accountID, label, email string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return Mailbox{}, errCode("provider_not_configured", "当前 MVP 需要先手动填入已创建的隐私邮箱；自动创建接口留给后续 iCloud Provider 接入", false)
	}
	for _, mailbox := range s.state.Mailboxes {
		if strings.EqualFold(mailbox.Email, email) {
			return Mailbox{}, errCode("mailbox_exists", "邮箱已存在", false)
		}
	}

	now := time.Now()
	token, err := randomToken(24)
	if err != nil {
		return Mailbox{}, err
	}
	if strings.TrimSpace(label) == "" {
		label = fmt.Sprintf("UPI-%s", time.Now().Format("0102-150405"))
	}
	mailbox := Mailbox{
		ID:           s.nextIDLocked("mbx"),
		BrowserKey:   strings.TrimSpace(browserKey),
		AccountID:    strings.TrimSpace(accountID),
		Label:        strings.TrimSpace(label),
		Email:        email,
		APIToken:     token,
		APIActive:    true,
		ICloudActive: true,
		Status:       StatusAvailable,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.state.Mailboxes = append(s.state.Mailboxes, mailbox)
	return mailbox, s.saveLocked()
}

func (s *FileStore) ClaimAvailableMailbox(note string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, mailbox := range s.state.Mailboxes {
		if !mailbox.APIActive || !mailbox.ICloudActive || mailbox.Status != StatusAvailable {
			continue
		}
		s.state.Mailboxes[i].Status = StatusUsed
		if strings.TrimSpace(note) != "" {
			s.state.Mailboxes[i].Note = strings.TrimSpace(note)
		}
		s.state.Mailboxes[i].UpdatedAt = time.Now()
		return s.state.Mailboxes[i], s.saveLocked()
	}
	return Mailbox{}, errCode("no_available_mailbox", "没有可用隐私邮箱", false)
}

func (s *FileStore) SaveICloudSession(session ICloudSession) error {
	return s.SaveICloudSessionForBrowser("", session)
}

func (s *FileStore) SaveICloudSessionForBrowser(browserKey string, session ICloudSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	browserKey = strings.TrimSpace(browserKey)
	session.BrowserKey = browserKey
	if session.SavedAt.IsZero() {
		session.SavedAt = time.Now()
	}
	if browserKey != "" {
		for i, existing := range s.state.ICloudSessions {
			if constantTimeEqual(browserKey, existing.BrowserKey) {
				s.state.ICloudSessions[i] = session
				return s.saveLocked()
			}
		}
		s.state.ICloudSessions = append(s.state.ICloudSessions, session)
		return s.saveLocked()
	}
	s.state.ICloudSession = &session
	return s.saveLocked()
}

func (s *FileStore) ICloudSession() (ICloudSession, bool) {
	return s.ICloudSessionForBrowser("")
}

func (s *FileStore) ICloudSessionForBrowser(browserKey string) (ICloudSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	browserKey = strings.TrimSpace(browserKey)
	if browserKey != "" {
		for _, session := range s.state.ICloudSessions {
			if constantTimeEqual(browserKey, session.BrowserKey) {
				return cloneICloudSession(session), true
			}
		}
		return ICloudSession{}, false
	}
	if s.state.ICloudSession == nil {
		return ICloudSession{}, false
	}
	return cloneICloudSession(*s.state.ICloudSession), true
}

func (s *FileStore) AddMessage(mailboxID, subject, from, body string, receivedAt time.Time) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(mailboxID)
	if idx < 0 {
		return Message{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	msg := Message{
		ID:         s.nextIDLocked("msg"),
		BrowserKey: s.state.Mailboxes[idx].BrowserKey,
		MailboxID:  mailboxID,
		Subject:    strings.TrimSpace(subject),
		From:       strings.TrimSpace(from),
		Body:       body,
		ReceivedAt: receivedAt,
		CreatedAt:  time.Now(),
	}
	s.state.Messages = append(s.state.Messages, msg)
	s.state.Mailboxes[idx].ReceiveCount++
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	return msg, s.saveLocked()
}

func (s *FileStore) UpsertMessage(mailboxID, remoteID, source, subject, from, body string, receivedAt time.Time) (Message, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(mailboxID)
	if idx < 0 {
		return Message{}, false, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	remoteID = strings.TrimSpace(remoteID)
	if remoteID != "" {
		for i, msg := range s.state.Messages {
			if msg.MailboxID == mailboxID && msg.RemoteID == remoteID {
				s.state.Messages[i].BrowserKey = s.state.Mailboxes[idx].BrowserKey
				s.state.Messages[i].Source = strings.TrimSpace(source)
				s.state.Messages[i].Subject = strings.TrimSpace(subject)
				s.state.Messages[i].From = strings.TrimSpace(from)
				s.state.Messages[i].Body = body
				if !receivedAt.IsZero() {
					s.state.Messages[i].ReceivedAt = receivedAt
				}
				s.state.Messages[i].CreatedAt = firstNonZeroTime(s.state.Messages[i].CreatedAt, time.Now())
				s.state.Mailboxes[idx].UpdatedAt = time.Now()
				return s.state.Messages[i], false, s.saveLocked()
			}
		}
	}
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	msg := Message{
		ID:         s.nextIDLocked("msg"),
		BrowserKey: s.state.Mailboxes[idx].BrowserKey,
		MailboxID:  mailboxID,
		RemoteID:   remoteID,
		Source:     strings.TrimSpace(source),
		Subject:    strings.TrimSpace(subject),
		From:       strings.TrimSpace(from),
		Body:       body,
		ReceivedAt: receivedAt,
		CreatedAt:  time.Now(),
	}
	s.state.Messages = append(s.state.Messages, msg)
	s.state.Mailboxes[idx].ReceiveCount++
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	return msg, true, s.saveLocked()
}

func (s *FileStore) SetMailboxStatus(id string, apiActive *bool, icloudActive *bool, status, note string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return Mailbox{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if apiActive != nil {
		s.state.Mailboxes[idx].APIActive = *apiActive
	}
	if icloudActive != nil {
		s.state.Mailboxes[idx].ICloudActive = *icloudActive
	}
	if strings.TrimSpace(status) != "" {
		s.state.Mailboxes[idx].Status = strings.TrimSpace(status)
	}
	if strings.TrimSpace(note) != "" {
		s.state.Mailboxes[idx].Note = strings.TrimSpace(note)
	}
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	return s.state.Mailboxes[idx], s.saveLocked()
}

func (s *FileStore) DeleteMailbox(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return errCode("mailbox_not_found", "邮箱不存在", false)
	}
	s.state.Mailboxes = append(s.state.Mailboxes[:idx], s.state.Mailboxes[idx+1:]...)
	filtered := s.state.Messages[:0]
	for _, msg := range s.state.Messages {
		if msg.MailboxID != id {
			filtered = append(filtered, msg)
		}
	}
	s.state.Messages = filtered
	return s.saveLocked()
}

func (s *FileStore) FindMailboxByID(id string) (Mailbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return Mailbox{}, false
	}
	return s.state.Mailboxes[idx], true
}

func (s *FileStore) FindMailboxByEmail(email string) (Mailbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, mailbox := range s.state.Mailboxes {
		if strings.EqualFold(mailbox.Email, email) {
			return mailbox, true
		}
	}
	return Mailbox{}, false
}

func (s *FileStore) MessagesForMailbox(mailboxID string) []Message {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Message
	for _, msg := range s.state.Messages {
		if msg.MailboxID == mailboxID {
			out = append(out, msg)
		}
	}
	return out
}

func (s *FileStore) nextIDLocked(prefix string) string {
	id := fmt.Sprintf("%s_%06d", prefix, s.state.NextID)
	s.state.NextID++
	return id
}

func (s *FileStore) mailboxIndexLocked(id string) int {
	for i, mailbox := range s.state.Mailboxes {
		if mailbox.ID == id {
			return i
		}
	}
	return -1
}

func (s *FileStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func cloneState(in State) State {
	out := in
	out.BrowserClients = append([]BrowserClient(nil), in.BrowserClients...)
	out.Accounts = append([]Account(nil), in.Accounts...)
	out.Mailboxes = append([]Mailbox(nil), in.Mailboxes...)
	out.Messages = append([]Message(nil), in.Messages...)
	if in.ICloudSession != nil {
		session := cloneICloudSession(*in.ICloudSession)
		out.ICloudSession = &session
	}
	out.ICloudSessions = cloneICloudSessions(in.ICloudSessions)
	return out
}

func cloneICloudSession(in ICloudSession) ICloudSession {
	out := in
	out.Cookies = append([]SessionCookie(nil), in.Cookies...)
	return out
}

func cloneICloudSessions(in []ICloudSession) []ICloudSession {
	out := make([]ICloudSession, 0, len(in))
	for _, session := range in {
		out = append(out, cloneICloudSession(session))
	}
	return out
}

func filterStateByBrowserKeyLocked(in State, browserKey string) State {
	if browserKey == "" {
		return cloneState(in)
	}
	out := State{NextID: in.NextID}
	for _, client := range in.BrowserClients {
		if constantTimeEqual(browserKey, client.Key) {
			out.BrowserClients = append(out.BrowserClients, client)
			break
		}
	}
	for _, account := range in.Accounts {
		if constantTimeEqual(browserKey, account.BrowserKey) {
			out.Accounts = append(out.Accounts, account)
		}
	}
	allowedMailboxes := make(map[string]struct{})
	for _, mailbox := range in.Mailboxes {
		if constantTimeEqual(browserKey, mailbox.BrowserKey) {
			out.Mailboxes = append(out.Mailboxes, mailbox)
			allowedMailboxes[mailbox.ID] = struct{}{}
		}
	}
	for _, msg := range in.Messages {
		if _, ok := allowedMailboxes[msg.MailboxID]; ok || constantTimeEqual(browserKey, msg.BrowserKey) {
			out.Messages = append(out.Messages, msg)
		}
	}
	for _, session := range in.ICloudSessions {
		if constantTimeEqual(browserKey, session.BrowserKey) {
			cloned := cloneICloudSession(session)
			out.ICloudSession = &cloned
			out.ICloudSessions = append(out.ICloudSessions, cloned)
			break
		}
	}
	return out
}

type codedError struct {
	code      string
	message   string
	retryable bool
}

func (e codedError) Error() string { return e.message }

func errCode(code, message string, retryable bool) error {
	return codedError{code: code, message: message, retryable: retryable}
}

func firstNonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}
