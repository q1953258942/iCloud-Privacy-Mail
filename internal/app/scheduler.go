package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultMailboxSchedulerBatchSize = 1
	defaultMailboxSchedulerInterval  = 60 * time.Minute
	maxMailboxSchedulerBatchSize     = 200
	maxMailboxSchedulerEvents        = 200
)

var defaultMailboxSchedulerRoundInterval = 5 * time.Second

type mailboxSchedulerConfig struct {
	AccountIDs    []string
	Label         string
	Note          string
	BatchSize     int
	Interval      time.Duration
	RoundInterval time.Duration
}

type mailboxSchedulerJob struct {
	mu          sync.Mutex
	cancel      context.CancelFunc
	nextEventID int64
	state       mailboxSchedulerState
	events      []mailboxSchedulerEvent
}

type mailboxSchedulerState struct {
	Running              bool
	OwnerID              string
	Owner                string
	AccountID            string
	AccountIDs           []string
	Label                string
	Note                 string
	BatchSize            int
	IntervalSeconds      int
	RoundIntervalSeconds int
	Status               string
	BatchIndex           int
	Success              int
	Failed               int
	StartedAt            time.Time
	LastRunAt            time.Time
	NextRunAt            time.Time
	StoppedAt            time.Time
	LastError            string
}

type mailboxSchedulerEvent struct {
	ID        int64
	At        time.Time
	Type      string
	Message   string
	Batch     int
	MailboxID string
	Email     string
	Error     string
}

type publicMailboxScheduler struct {
	Running              bool                          `json:"running"`
	Owner                string                        `json:"owner,omitempty"`
	AccountID            string                        `json:"account_id,omitempty"`
	AccountIDs           []string                      `json:"account_ids,omitempty"`
	Label                string                        `json:"label,omitempty"`
	Note                 string                        `json:"note,omitempty"`
	BatchSize            int                           `json:"batch_size"`
	IntervalSeconds      int                           `json:"interval_seconds"`
	IntervalMinutes      int                           `json:"interval_minutes"`
	RoundIntervalSeconds int                           `json:"round_interval_seconds"`
	Status               string                        `json:"status"`
	BatchIndex           int                           `json:"batch_index"`
	Success              int                           `json:"success"`
	Failed               int                           `json:"failed"`
	StartedAt            string                        `json:"started_at,omitempty"`
	LastRunAt            string                        `json:"last_run_at,omitempty"`
	NextRunAt            string                        `json:"next_run_at,omitempty"`
	StoppedAt            string                        `json:"stopped_at,omitempty"`
	LastError            string                        `json:"last_error,omitempty"`
	Events               []publicMailboxSchedulerEvent `json:"events"`
}

type publicMailboxSchedulerEvent struct {
	ID        int64  `json:"id"`
	At        string `json:"at"`
	Type      string `json:"type"`
	Message   string `json:"message"`
	Batch     int    `json:"batch,omitempty"`
	MailboxID string `json:"mailbox_id,omitempty"`
	Email     string `json:"email,omitempty"`
	APIURL    string `json:"api_url,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (s *Server) handleMailboxSchedulerStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"scheduler": s.publicMailboxScheduler(r),
	})
}

func (s *Server) handleStartMailboxScheduler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID            string   `json:"account_id"`
		AccountIDs           []string `json:"account_ids"`
		Label                string   `json:"label"`
		Note                 string   `json:"note"`
		BatchSize            int      `json:"batch_size"`
		IntervalMinutes      int      `json:"interval_minutes"`
		IntervalSeconds      int      `json:"interval_seconds"`
		RoundIntervalSeconds int      `json:"round_interval_seconds"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	ownerID := requestOwnerID(r, s.store)
	if ownerID == "" {
		writeError(w, http.StatusUnauthorized, errCode("auth_required", "请先登录账号", false))
		return
	}
	accountIDs := normalizeAccountIDSelection(payload.AccountID, payload.AccountIDs)
	for _, accountID := range accountIDs {
		if !s.canAccessAccountIDForOwner(ownerID, accountID) {
			writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
			return
		}
	}
	if len(s.sessionsForOwnerAccounts(ownerID, accountIDs)) == 0 {
		writeError(w, http.StatusBadRequest, errCode("icloud_session_missing", "未找到可用于创建的 iCloud 登录态，请检查参与账号 ID 或先保存登录态", true))
		return
	}

	cfg := mailboxSchedulerConfig{
		AccountIDs:    accountIDs,
		Label:         strings.TrimSpace(payload.Label),
		Note:          strings.TrimSpace(payload.Note),
		BatchSize:     defaultMailboxSchedulerBatchSize,
		Interval:      defaultMailboxSchedulerInterval,
		RoundInterval: defaultMailboxSchedulerRoundInterval,
	}
	if payload.IntervalSeconds > 0 {
		cfg.Interval = time.Duration(payload.IntervalSeconds) * time.Second
	} else if payload.IntervalMinutes > 0 {
		cfg.Interval = time.Duration(payload.IntervalMinutes) * time.Minute
	}
	if cfg.Interval < time.Second {
		cfg.Interval = time.Second
	}
	if payload.RoundIntervalSeconds > 0 {
		cfg.RoundInterval = time.Duration(payload.RoundIntervalSeconds) * time.Second
		if cfg.RoundInterval < time.Second {
			cfg.RoundInterval = time.Second
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	job := &mailboxSchedulerJob{
		cancel: cancel,
		state: mailboxSchedulerState{
			Running:              true,
			OwnerID:              ownerID,
			Owner:                s.ownerName(ownerID),
			AccountID:            strings.Join(cfg.AccountIDs, ","),
			AccountIDs:           append([]string(nil), cfg.AccountIDs...),
			Label:                cfg.Label,
			Note:                 cfg.Note,
			BatchSize:            cfg.BatchSize,
			IntervalSeconds:      int(cfg.Interval.Round(time.Second).Seconds()),
			RoundIntervalSeconds: int(cfg.RoundInterval.Round(time.Second).Seconds()),
			Status:               "running",
			StartedAt:            time.Now(),
		},
	}
	job.addEventLocked("started", "定时创建已启动", 0, Mailbox{}, nil)

	s.schedulerMu.Lock()
	if old := s.mailboxSchedulers[ownerID]; old != nil && old.running() {
		s.schedulerMu.Unlock()
		cancel()
		writeError(w, http.StatusConflict, errCode("scheduler_running", "定时创建已经在运行，请先停止后再启动", false))
		return
	}
	s.mailboxSchedulers[ownerID] = job
	s.schedulerMu.Unlock()

	go s.runMailboxScheduler(ctx, ownerID, job, cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"scheduler": s.publicMailboxScheduler(r),
	})
}

func (s *Server) handleStopMailboxScheduler(w http.ResponseWriter, r *http.Request) {
	ownerID := requestOwnerID(r, s.store)
	if ownerID == "" {
		writeError(w, http.StatusUnauthorized, errCode("auth_required", "请先登录账号", false))
		return
	}
	job := s.mailboxScheduler(ownerID)
	if job == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"success":   true,
			"scheduler": s.publicMailboxScheduler(r),
		})
		return
	}
	job.stop("已手动停止定时创建")
	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"scheduler": s.publicMailboxScheduler(r),
	})
}

func (s *Server) handleClearMailboxSchedulerLogs(w http.ResponseWriter, r *http.Request) {
	ownerID := requestOwnerID(r, s.store)
	if ownerID == "" {
		writeError(w, http.StatusUnauthorized, errCode("auth_required", "请先登录账号", false))
		return
	}
	if job := s.mailboxScheduler(ownerID); job != nil {
		job.clearEvents()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"message":   "定时创建记录已清除",
		"scheduler": s.publicMailboxScheduler(r),
	})
}

func (s *Server) runMailboxScheduler(ctx context.Context, ownerID string, job *mailboxSchedulerJob, cfg mailboxSchedulerConfig) {
	defer func() {
		job.mu.Lock()
		if job.state.Running {
			job.state.Running = false
			job.state.Status = "stopped"
			job.state.StoppedAt = time.Now()
			job.addEventLocked("stopped", "定时创建已停止", job.state.BatchIndex, Mailbox{}, nil)
		}
		job.cancel = nil
		job.mu.Unlock()
	}()

	for {
		if ctx.Err() != nil {
			return
		}
		job.mu.Lock()
		job.state.BatchIndex++
		batch := job.state.BatchIndex
		job.state.Status = "creating"
		job.state.LastRunAt = time.Now()
		job.state.NextRunAt = time.Time{}
		job.addEventLocked("batch_started", schedulerBatchStartedMessage(batch), batch, Mailbox{}, nil)
		job.mu.Unlock()

		s.runMailboxSchedulerBatch(ctx, ownerID, job, cfg, batch)
		if ctx.Err() != nil {
			return
		}

		nextRunAt := time.Now().Add(cfg.Interval)
		job.mu.Lock()
		job.state.Status = "waiting"
		job.state.NextRunAt = nextRunAt
		job.addEventLocked("waiting", fmt.Sprintf("进入等待：%s 后重新尝试全部账号", cfg.Interval.Round(time.Second)), batch, Mailbox{}, nil)
		job.mu.Unlock()

		timer := time.NewTimer(cfg.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *Server) runMailboxSchedulerBatch(ctx context.Context, ownerID string, job *mailboxSchedulerJob, cfg mailboxSchedulerConfig, batch int) {
	batchAccountIDs := normalizeAccountIDSelection("", cfg.AccountIDs)
	if len(batchAccountIDs) == 0 {
		for _, session := range s.sessionsForOwnerAccounts(ownerID, cfg.AccountIDs) {
			if accountID := strings.TrimSpace(session.AccountID); accountID != "" {
				batchAccountIDs = append(batchAccountIDs, accountID)
			}
		}
	}
	accountChannels := s.schedulerCreateChannelsByAccount(ownerID, batchAccountIDs)
	disabledChannels := make(map[string]map[mailboxCreateChannel]bool)
	skippedThisBatch := make(map[string]bool)
	for _, accountID := range batchAccountIDs {
		accountID = strings.TrimSpace(accountID)
		if accountID == "" || len(accountChannels[accountID]) > 0 {
			continue
		}
		skippedThisBatch[accountID] = true
		message := "未保存新接口或旧接口登录态"
		job.mu.Lock()
		job.state.Failed++
		job.state.LastError = message
		job.addEventLocked("failed", schedulerAccountFailedMessage(0, "", mailboxCreateChannelAuto, message), batch, Mailbox{}, errors.New(message))
		job.mu.Unlock()
	}
	for index := 1; ; index++ {
		if ctx.Err() != nil {
			return
		}
		activeRequests := activeSchedulerCreateRequests(batchAccountIDs, accountChannels, disabledChannels, skippedThisBatch)
		if len(activeRequests) == 0 {
			job.mu.Lock()
			job.addEventLocked("skipped", fmt.Sprintf("第 %d 次定时创建剩余账号都已临时跳过，下一次定时创建会重新尝试", batch), batch, Mailbox{}, nil)
			job.mu.Unlock()
			return
		}
		label := schedulerMailboxLabel(cfg.Label, batch, index, 0)
		mailboxes, remotes, failures, err := s.createMailboxesForOwnerWithChannels(ctx, ownerID, activeRequests, label, cfg.Note)
		if err != nil && len(mailboxes) == 0 && len(failures) == 0 {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			s.logICloudCreateError(ownerID, err)
			message := schedulerErrorMessage(err)
			job.mu.Lock()
			job.state.Failed++
			job.state.LastError = message
			job.addEventLocked("failed", schedulerBatchFailedMessage(index, message), batch, Mailbox{}, err)
			job.mu.Unlock()
			return
		}
		job.mu.Lock()
		job.state.Success += len(mailboxes)
		job.state.LastError = ""
		for mailboxIndex, mailbox := range mailboxes {
			channel := mailboxCreateChannelAuto
			if mailboxIndex < len(remotes) {
				channel = mailboxCreateChannelFromRemote(remotes[mailboxIndex])
			}
			job.addEventLocked("created", schedulerMailboxCreatedMessage(index, s.schedulerMailboxAccountLabel(mailbox.AccountID), channel, mailbox.Email), batch, mailbox, nil)
		}
		if len(failures) > 0 {
			for _, failure := range failures {
				accountID := strings.TrimSpace(failure.AccountID)
				accountLabel := schedulerFailureAccountLabel(failure)
				channel := normalizeMailboxCreateChannel(mailboxCreateChannel(failure.Channel))
				if channel == mailboxCreateChannelAuto {
					channel = activeRequestChannel(activeRequests, accountID)
				}
				if accountID != "" && channel != mailboxCreateChannelAuto {
					disableSchedulerCreateChannel(disabledChannels, accountID, channel)
				}
				if accountID != "" {
					if nextChannel, ok := nextSchedulerCreateChannel(accountChannels[accountID], disabledChannels[accountID]); ok {
						job.state.LastError = failure.Error
						job.addEventLocked("channel_failed", schedulerChannelFailedMessage(index, accountLabel, channel, failure.Error, nextChannel), batch, Mailbox{}, errors.New(failure.Error))
						continue
					}
					skippedThisBatch[accountID] = true
				}
				job.state.Failed++
				job.state.LastError = failure.Error
				job.addEventLocked("failed", schedulerAccountFailedMessage(index, accountLabel, channel, failure.Error), batch, Mailbox{}, errors.New(failure.Error))
			}
		}
		hasNextRound := len(activeSchedulerCreateRequests(batchAccountIDs, accountChannels, disabledChannels, skippedThisBatch)) > 0
		job.mu.Unlock()
		if hasNextRound {
			if err := waitMailboxSchedulerRoundInterval(ctx, cfg.RoundInterval); err != nil {
				return
			}
		}
	}
}

func waitMailboxSchedulerRoundInterval(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return nil
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func schedulerBatchStartedMessage(batch int) string {
	return fmt.Sprintf("开始第 %d 次定时创建：勾选账号同时创建，失败账号本轮临时跳过，直到全部临时失败后等待下次", batch)
}

func schedulerBatchFailedMessage(index int, message string) string {
	return fmt.Sprintf("第 %d 轮创建失败：%s", index, message)
}

func schedulerMailboxCreatedMessage(index int, account string, channel mailboxCreateChannel, email string) string {
	account = strings.TrimSpace(account)
	if account == "" {
		account = "未知账号"
	}
	return fmt.Sprintf("第 %d 轮%s使用%s创建成功：%s", index, account, mailboxCreateChannelLabel(channel), email)
}

func schedulerAccountFailedMessage(index int, account string, channel mailboxCreateChannel, message string) string {
	if index <= 0 {
		return fmt.Sprintf("账号创建失败：%s，本次定时创建临时跳过该账号，下一次定时创建再试", message)
	}
	account = strings.TrimSpace(account)
	if account == "" {
		account = "未知账号"
	}
	return fmt.Sprintf("第 %d 轮%s使用%s创建失败：%s；该账号本轮已无可用接口，本次定时创建临时跳过该账号，下一次定时创建再试", index, account, mailboxCreateChannelLabel(channel), message)
}

func schedulerChannelFailedMessage(index int, account string, channel mailboxCreateChannel, message string, nextChannel mailboxCreateChannel) string {
	account = strings.TrimSpace(account)
	if account == "" {
		account = "未知账号"
	}
	return fmt.Sprintf("第 %d 轮%s使用%s创建失败：%s；本轮切换%s继续尝试", index, account, mailboxCreateChannelLabel(channel), message, mailboxCreateChannelLabel(nextChannel))
}

func mailboxCreateChannelFromRemote(remote ICloudRemoteMailbox) mailboxCreateChannel {
	origin := strings.TrimSpace(remote.Origin)
	if channel := normalizeMailboxCreateChannel(mailboxCreateChannel(strings.ToLower(origin))); channel != mailboxCreateChannelAuto {
		return channel
	}
	if strings.EqualFold(origin, "APPLE_ACCOUNT") {
		return mailboxCreateChannelAppleAccount
	}
	if strings.TrimSpace(remote.Email) != "" {
		return mailboxCreateChannelICloudWeb
	}
	return mailboxCreateChannelAuto
}

func (s *Server) schedulerMailboxAccountLabel(accountID string) string {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return ""
	}
	if account, ok := s.store.FindAccountByID(accountID); ok {
		return firstNonEmpty(strings.TrimSpace(account.AppleID), strings.TrimSpace(account.Label), accountID)
	}
	return accountID
}

func schedulerFailureAccountLabel(failure createMailboxFailure) string {
	return firstNonEmpty(strings.TrimSpace(failure.AppleID), strings.TrimSpace(failure.AccountID))
}

func (s *Server) schedulerCreateChannelsByAccount(ownerID string, accountIDs []string) map[string][]mailboxCreateChannel {
	out := make(map[string][]mailboxCreateChannel)
	for _, session := range s.sessionsForOwnerAccounts(ownerID, accountIDs) {
		accountID := strings.TrimSpace(session.AccountID)
		if accountID == "" {
			continue
		}
		out[accountID] = schedulerCreateChannelsForSession(session)
	}
	return out
}

func schedulerCreateChannelsForSession(session ICloudSession) []mailboxCreateChannel {
	channels := make([]mailboxCreateChannel, 0, 2)
	if _, ok := appleAccountLoginState(session); ok {
		channels = append(channels, mailboxCreateChannelAppleAccount)
	}
	if iCloudWebLoginSaved(session) {
		channels = append(channels, mailboxCreateChannelICloudWeb)
	}
	return channels
}

func activeSchedulerCreateRequests(accountIDs []string, channels map[string][]mailboxCreateChannel, disabled map[string]map[mailboxCreateChannel]bool, skipped map[string]bool) []mailboxCreateRequest {
	out := make([]mailboxCreateRequest, 0, len(accountIDs))
	for _, accountID := range normalizeAccountIDSelection("", accountIDs) {
		accountID = strings.TrimSpace(accountID)
		if accountID == "" || skipped[accountID] {
			continue
		}
		channel, ok := nextSchedulerCreateChannel(channels[accountID], disabled[accountID])
		if !ok {
			continue
		}
		out = append(out, mailboxCreateRequest{AccountID: accountID, Channel: channel})
	}
	return out
}

func nextSchedulerCreateChannel(channels []mailboxCreateChannel, disabled map[mailboxCreateChannel]bool) (mailboxCreateChannel, bool) {
	for _, channel := range channels {
		channel = normalizeMailboxCreateChannel(channel)
		if channel == mailboxCreateChannelAuto {
			continue
		}
		if disabled != nil && disabled[channel] {
			continue
		}
		return channel, true
	}
	return mailboxCreateChannelAuto, false
}

func disableSchedulerCreateChannel(disabled map[string]map[mailboxCreateChannel]bool, accountID string, channel mailboxCreateChannel) {
	channel = normalizeMailboxCreateChannel(channel)
	if accountID == "" || channel == mailboxCreateChannelAuto {
		return
	}
	if disabled[accountID] == nil {
		disabled[accountID] = make(map[mailboxCreateChannel]bool)
	}
	disabled[accountID][channel] = true
}

func activeRequestChannel(requests []mailboxCreateRequest, accountID string) mailboxCreateChannel {
	accountID = strings.TrimSpace(accountID)
	for _, request := range requests {
		if strings.TrimSpace(request.AccountID) == accountID {
			return normalizeMailboxCreateChannel(request.Channel)
		}
	}
	return mailboxCreateChannelAuto
}

func (s *Server) mailboxScheduler(ownerID string) *mailboxSchedulerJob {
	s.schedulerMu.Lock()
	defer s.schedulerMu.Unlock()
	return s.mailboxSchedulers[strings.TrimSpace(ownerID)]
}

func (s *Server) publicMailboxScheduler(r *http.Request) publicMailboxScheduler {
	ownerID := requestOwnerID(r, s.store)
	job := s.mailboxScheduler(ownerID)
	if job == nil {
		return publicMailboxScheduler{
			BatchSize:            defaultMailboxSchedulerBatchSize,
			IntervalSeconds:      int(defaultMailboxSchedulerInterval.Seconds()),
			IntervalMinutes:      int(defaultMailboxSchedulerInterval.Minutes()),
			RoundIntervalSeconds: int(defaultMailboxSchedulerRoundInterval.Seconds()),
			Status:               "stopped",
			Events:               []publicMailboxSchedulerEvent{},
		}
	}
	state, events := job.snapshot()
	out := publicMailboxScheduler{
		Running:              state.Running,
		Owner:                state.Owner,
		AccountID:            state.AccountID,
		AccountIDs:           append([]string(nil), state.AccountIDs...),
		Label:                state.Label,
		Note:                 state.Note,
		BatchSize:            state.BatchSize,
		IntervalSeconds:      state.IntervalSeconds,
		IntervalMinutes:      state.IntervalSeconds / 60,
		RoundIntervalSeconds: state.RoundIntervalSeconds,
		Status:               state.Status,
		BatchIndex:           state.BatchIndex,
		Success:              state.Success,
		Failed:               state.Failed,
		StartedAt:            formatTime(state.StartedAt),
		LastRunAt:            formatTime(state.LastRunAt),
		NextRunAt:            formatTime(state.NextRunAt),
		StoppedAt:            formatTime(state.StoppedAt),
		LastError:            state.LastError,
		Events:               make([]publicMailboxSchedulerEvent, 0, len(events)),
	}
	for _, event := range events {
		item := publicMailboxSchedulerEvent{
			ID:        event.ID,
			At:        formatTime(event.At),
			Type:      event.Type,
			Message:   event.Message,
			Batch:     event.Batch,
			MailboxID: event.MailboxID,
			Email:     event.Email,
			Error:     event.Error,
		}
		if event.MailboxID != "" {
			if mailbox, ok := s.store.FindMailboxByID(event.MailboxID); ok && (ownerID == "" || constantTimeEqual(ownerID, mailbox.OwnerID) || s.isAdminRequest(r)) {
				item.APIURL = s.mailboxAPIURL(r, mailbox)
			}
		}
		out.Events = append(out.Events, item)
	}
	return out
}

func (j *mailboxSchedulerJob) running() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state.Running
}

func (j *mailboxSchedulerJob) stop(message string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cancel != nil {
		j.cancel()
		j.cancel = nil
	}
	if j.state.Running {
		j.state.Running = false
		j.state.Status = "stopped"
		j.state.NextRunAt = time.Time{}
		j.state.StoppedAt = time.Now()
		j.addEventLocked("stopped", message, j.state.BatchIndex, Mailbox{}, nil)
	}
}

func (j *mailboxSchedulerJob) snapshot() (mailboxSchedulerState, []mailboxSchedulerEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	state := j.state
	events := make([]mailboxSchedulerEvent, len(j.events))
	copy(events, j.events)
	return state, events
}

func (j *mailboxSchedulerJob) clearEvents() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.events = nil
}

func (j *mailboxSchedulerJob) addEventLocked(kind, message string, batch int, mailbox Mailbox, err error) {
	j.nextEventID++
	event := mailboxSchedulerEvent{
		ID:      j.nextEventID,
		At:      time.Now(),
		Type:    kind,
		Message: message,
		Batch:   batch,
	}
	if mailbox.ID != "" {
		event.MailboxID = mailbox.ID
		event.Email = mailbox.Email
	}
	if err != nil {
		event.Error = schedulerErrorMessage(err)
	}
	j.events = append([]mailboxSchedulerEvent{event}, j.events...)
	if len(j.events) > maxMailboxSchedulerEvents {
		j.events = j.events[:maxMailboxSchedulerEvents]
	}
}

func schedulerMailboxLabel(base string, batch, index, total int) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "UPI-" + time.Now().Format("0102-150405")
	}
	if total <= 0 {
		if index <= 1 {
			return base
		}
		return fmt.Sprintf("%s-B%03d-%02d", base, batch, index)
	}
	if total <= 1 {
		return base
	}
	width := len(fmt.Sprintf("%d", total))
	if width < 2 {
		width = 2
	}
	return fmt.Sprintf("%s-B%03d-%0*d", base, batch, width, index)
}

func schedulerErrorMessage(err error) string {
	var coded codedError
	if errors.As(err, &coded) {
		return coded.message
	}
	return err.Error()
}
