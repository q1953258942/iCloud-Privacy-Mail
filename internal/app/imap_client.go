package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

const (
	defaultICloudIMAPHost = "imap.mail.me.com"
	defaultICloudIMAPPort = 993
)

func CheckICloudIMAPLogin(ctx context.Context, email, appPassword string) error {
	email = strings.TrimSpace(email)
	appPassword = strings.TrimSpace(appPassword)
	if email == "" {
		return errCode("imap_email_missing", "请输入 iCloud 邮箱账号", false)
	}
	if appPassword == "" {
		return errCode("imap_app_password_missing", "请输入 App 专用密码", false)
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	address := net.JoinHostPort(defaultICloudIMAPHost, strconv.Itoa(defaultICloudIMAPPort))
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 15 * time.Second},
		Config: &tls.Config{
			ServerName: defaultICloudIMAPHost,
			MinVersion: tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return errCode("imap_connect_failed", "连接 iCloud IMAP 失败："+err.Error(), true)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return errCode("imap_greeting_failed", "读取 iCloud IMAP 欢迎信息失败："+err.Error(), true)
	}
	if !strings.Contains(strings.ToUpper(greeting), "OK") {
		return errCode("imap_greeting_failed", "iCloud IMAP 未就绪："+imapResponseSummary([]string{greeting}), true)
	}

	loginLines, err := imapCommand(conn, reader, "A001", "LOGIN "+imapQuote(email)+" "+imapQuote(appPassword))
	if err != nil {
		return errCode("imap_login_failed", "iCloud IMAP 登录请求失败："+err.Error(), true)
	}
	if !imapTaggedOK(loginLines, "A001") {
		return errCode("imap_login_failed", "iCloud IMAP 登录失败，请确认 iCloud 邮箱账号和 App 专用密码："+imapResponseSummary(loginLines), false)
	}

	selectLines, err := imapCommand(conn, reader, "A002", "SELECT INBOX")
	if err != nil {
		return errCode("imap_select_failed", "打开 iCloud 收件箱失败："+err.Error(), true)
	}
	if !imapTaggedOK(selectLines, "A002") {
		return errCode("imap_select_failed", "打开 iCloud 收件箱失败："+imapResponseSummary(selectLines), true)
	}
	_, _ = imapCommand(conn, reader, "A003", "LOGOUT")
	return nil
}

func imapCommand(conn net.Conn, reader *bufio.Reader, tag, command string) ([]string, error) {
	lines, _, err := imapCommandWithLiterals(conn, reader, tag, command)
	return lines, err
}

func imapCommandWithLiterals(conn net.Conn, reader *bufio.Reader, tag, command string) ([]string, [][]byte, error) {
	if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, command); err != nil {
		return nil, nil, err
	}
	lines := make([]string, 0, 4)
	literals := make([][]byte, 0)
	for i := 0; i < 200; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			return lines, literals, err
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, strings.TrimSpace(line))
		if n, ok := imapLiteralSize(line); ok {
			body := make([]byte, n)
			if _, err := io.ReadFull(reader, body); err != nil {
				return lines, literals, err
			}
			literals = append(literals, body)
		}
		if strings.HasPrefix(strings.TrimSpace(line), tag+" ") {
			return lines, literals, nil
		}
	}
	return lines, literals, errors.New("IMAP 响应过长")
}

func imapTaggedOK(lines []string, tag string) bool {
	for _, line := range lines {
		upper := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(upper, strings.ToUpper(tag)+" ") {
			return strings.Contains(upper, " OK")
		}
	}
	return false
}

func imapQuote(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return `"` + value + `"`
}

func imapResponseSummary(lines []string) string {
	joined := strings.Join(lines, "；")
	return trimForError([]byte(joined))
}

func SyncICloudIMAPMessages(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
	state, err := normalizeICloudIMAPState(state)
	if err != nil {
		return nil, err
	}
	if maxMessages <= 0 {
		maxMessages = 50
	}
	if maxMessages > 200 {
		maxMessages = 200
	}
	if keyword = strings.TrimSpace(keyword); keyword == "" {
		keyword = "OpenAI"
	}
	if len(mailboxes) == 0 {
		return map[string][]ICloudSyncedMessage{}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	address := net.JoinHostPort(state.IMAPHost, strconv.Itoa(state.IMAPPort))
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 15 * time.Second},
		Config: &tls.Config{
			ServerName: state.IMAPHost,
			MinVersion: tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, errCode("imap_connect_failed", "连接 iCloud IMAP 失败："+err.Error(), true)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return nil, errCode("imap_greeting_failed", "读取 iCloud IMAP 欢迎信息失败："+err.Error(), true)
	}
	if !strings.Contains(strings.ToUpper(greeting), "OK") {
		return nil, errCode("imap_greeting_failed", "iCloud IMAP 未就绪："+imapResponseSummary([]string{greeting}), true)
	}
	loginLines, err := imapCommand(conn, reader, "A001", "LOGIN "+imapQuote(state.IMAPUsername)+" "+imapQuote(state.IMAPAppPassword))
	if err != nil {
		return nil, errCode("imap_login_failed", "iCloud IMAP 登录请求失败："+err.Error(), true)
	}
	if !imapTaggedOK(loginLines, "A001") {
		return nil, errCode("imap_login_failed", "iCloud IMAP 登录失败，请确认 iCloud 邮箱账号和 App 专用密码："+imapResponseSummary(loginLines), false)
	}
	selectLines, err := imapCommand(conn, reader, "A002", "SELECT INBOX")
	if err != nil {
		return nil, errCode("imap_select_failed", "打开 iCloud 收件箱失败："+err.Error(), true)
	}
	if !imapTaggedOK(selectLines, "A002") {
		return nil, errCode("imap_select_failed", "打开 iCloud 收件箱失败："+imapResponseSummary(selectLines), true)
	}
	searchAfter := after
	if searchAfter.IsZero() {
		searchAfter = time.Now().Add(-24 * time.Hour)
	}
	searchLines, err := imapCommand(conn, reader, "A003", "UID SEARCH SINCE "+searchAfter.Format("2-Jan-2006"))
	if err != nil {
		return nil, errCode("imap_search_failed", "搜索 iCloud IMAP 邮件失败："+err.Error(), true)
	}
	if !imapTaggedOK(searchLines, "A003") {
		return nil, errCode("imap_search_failed", "搜索 iCloud IMAP 邮件失败："+imapResponseSummary(searchLines), true)
	}
	uids := imapSearchUIDs(searchLines)
	if len(uids) == 0 {
		_, _ = imapCommand(conn, reader, "A004", "LOGOUT")
		return map[string][]ICloudSyncedMessage{}, nil
	}
	sortInts(uids)
	uids = lastIntValues(uids, maxMessages)

	fetched := make([]iCloudIMAPFetchedMessage, 0, len(uids))
	tag := 4
	for _, chunk := range chunkInts(uids, 20) {
		tag++
		lines, literals, err := imapCommandWithLiterals(conn, reader, fmt.Sprintf("A%03d", tag), "UID FETCH "+imapUIDSet(chunk)+" (UID BODY.PEEK[]<0.200000>)")
		if err != nil {
			return nil, errCode("imap_fetch_failed", "读取 iCloud IMAP 邮件失败："+err.Error(), true)
		}
		if !imapTaggedOK(lines, fmt.Sprintf("A%03d", tag)) {
			return nil, errCode("imap_fetch_failed", "读取 iCloud IMAP 邮件失败："+imapResponseSummary(lines), true)
		}
		fetchUIDs := imapFetchUIDs(lines)
		for i, raw := range literals {
			uid := ""
			if i < len(fetchUIDs) {
				uid = strconv.Itoa(fetchUIDs[i])
			}
			fetched = append(fetched, iCloudIMAPFetchedMessage{UID: uid, Raw: raw})
		}
	}
	_, _ = imapCommand(conn, reader, fmt.Sprintf("A%03d", tag+1), "LOGOUT")
	return iCloudIMAPMessagesByMailbox(fetched, mailboxes, after, keyword, state.IMAPEmail, state.IMAPUsername), nil
}

type iCloudIMAPFetchedMessage struct {
	UID string
	Raw []byte
}

func iCloudIMAPMessagesByMailbox(fetched []iCloudIMAPFetchedMessage, mailboxes []Mailbox, after time.Time, keyword string, ignoredEmails ...string) map[string][]ICloudSyncedMessage {
	now := time.Now()
	aliases := make(map[string]string)
	afterByMailbox := make(map[string]time.Time)
	ignored := make(map[string]struct{}, len(ignoredEmails))
	for _, email := range ignoredEmails {
		if email = normalizeICloudIMAPEmail(email); email != "" {
			ignored[email] = struct{}{}
		}
	}
	for _, mailbox := range mailboxes {
		id := strings.TrimSpace(mailbox.ID)
		email := normalizeICloudIMAPEmail(mailbox.Email)
		if id == "" || email == "" {
			continue
		}
		if _, skip := ignored[email]; skip {
			continue
		}
		aliases[id] = email
		afterByMailbox[id] = mailboxSyncAfter(mailbox, after, now)
	}
	out := make(map[string][]ICloudSyncedMessage, len(aliases))
	for _, item := range fetched {
		message, recipients, ok := parseICloudIMAPMessage(item)
		if !ok {
			continue
		}
		if !looksLikeVerificationText(message.Subject+"\n"+message.Body, keyword) {
			continue
		}
		matchedMailboxIDs := matchingMailboxIDs(recipients, aliases)
		if len(matchedMailboxIDs) == 0 {
			continue
		}
		for _, mailboxID := range matchedMailboxIDs {
			if after := afterByMailbox[mailboxID]; !after.IsZero() && message.ReceivedAt.Before(after) {
				continue
			}
			out[mailboxID] = append(out[mailboxID], message)
		}
	}
	for mailboxID := range out {
		sortMessagesByReceivedAt(out[mailboxID])
	}
	return out
}

func parseICloudIMAPMessage(item iCloudIMAPFetchedMessage) (ICloudSyncedMessage, string, bool) {
	msg, err := mail.ReadMessage(bytes.NewReader(item.Raw))
	if err != nil {
		return ICloudSyncedMessage{}, "", false
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(msg.Body, 1<<20))
	body := decodeICloudIMAPBody(msg.Header, bodyBytes)
	subject := decodeMIMEHeader(msg.Header.Get("Subject"))
	from := decodeMIMEHeader(msg.Header.Get("From"))
	receivedAt := time.Now()
	if date, err := msg.Header.Date(); err == nil {
		receivedAt = date
	}
	uid := strings.TrimSpace(item.UID)
	remoteID := "imap"
	if uid != "" {
		remoteID += ":" + uid
	}
	recipients := imapHeaderText(msg.Header)
	return ICloudSyncedMessage{
		RemoteID:   remoteID,
		UID:        uid,
		Subject:    subject,
		From:       from,
		Body:       normalizeMailBody(subject + "\n" + body),
		ReceivedAt: receivedAt,
	}, recipients, true
}

func normalizeICloudIMAPState(state LoginState) (LoginState, error) {
	email := normalizeICloudIMAPEmail(state.IMAPEmail)
	if email == "" {
		email = normalizeICloudIMAPEmail(state.IMAPUsername)
	}
	if email == "" {
		return LoginState{}, errCode("imap_session_missing", "未保存取码登录，请先保存 iCloud 邮箱账号和 App 专用密码", true)
	}
	appPassword := strings.TrimSpace(state.IMAPAppPassword)
	if appPassword == "" {
		return LoginState{}, errCode("imap_app_password_missing", "取码登录缺少 App 专用密码，请重新保存取码登录", false)
	}
	state.IMAPEmail = email
	state.IMAPUsername = firstNonEmpty(strings.TrimSpace(state.IMAPUsername), email)
	state.IMAPHost = firstNonEmpty(strings.TrimSpace(state.IMAPHost), defaultICloudIMAPHost)
	if state.IMAPPort == 0 {
		state.IMAPPort = defaultICloudIMAPPort
	}
	state.IMAPAppPassword = appPassword
	return state, nil
}

func imapLiteralSize(line string) (int, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasSuffix(line, "}") {
		return 0, false
	}
	start := strings.LastIndex(line, "{")
	if start < 0 || start+1 >= len(line) {
		return 0, false
	}
	value := strings.TrimSuffix(line[start+1:], "}")
	value = strings.TrimSuffix(value, "+")
	n, err := strconv.Atoi(value)
	return n, err == nil && n >= 0
}

func imapSearchUIDs(lines []string) []int {
	var out []int
	for _, line := range lines {
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "* SEARCH") {
			continue
		}
		for _, part := range strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "* SEARCH"))) {
			n, err := strconv.Atoi(part)
			if err == nil && n > 0 {
				out = append(out, n)
			}
		}
	}
	return out
}

func imapFetchUIDs(lines []string) []int {
	var out []int
	for _, line := range lines {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if strings.EqualFold(strings.Trim(fields[i], "()"), "UID") {
				value := strings.Trim(fields[i+1], "()")
				if n, err := strconv.Atoi(value); err == nil && n > 0 {
					out = append(out, n)
				}
			}
		}
	}
	return out
}

func sortInts(values []int) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func lastIntValues(values []int, limit int) []int {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return values[len(values)-limit:]
}

func chunkInts(values []int, size int) [][]int {
	if size <= 0 {
		size = len(values)
	}
	var out [][]int
	for start := 0; start < len(values); start += size {
		end := start + size
		if end > len(values) {
			end = len(values)
		}
		out = append(out, values[start:end])
	}
	return out
}

func imapUIDSet(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}

func imapHeaderText(header mail.Header) string {
	var out []string
	for key, values := range header {
		for _, value := range values {
			out = append(out, key+": "+decodeMIMEHeader(value))
		}
	}
	return strings.Join(out, "\n")
}

func decodeMIMEHeader(value string) string {
	decoded, err := new(mime.WordDecoder).DecodeHeader(value)
	if err != nil {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(decoded)
}

func decodeICloudIMAPBody(header mail.Header, body []byte) string {
	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(header.Get("Content-Type")))
	}
	decoded := decodeICloudIMAPTransfer(header.Get("Content-Transfer-Encoding"), body)
	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return string(decoded)
		}
		reader := multipart.NewReader(bytes.NewReader(decoded), boundary)
		var parts []string
		for i := 0; i < 30; i++ {
			part, err := reader.NextPart()
			if err != nil {
				break
			}
			partBody, _ := io.ReadAll(io.LimitReader(part, 1<<20))
			text := decodeICloudIMAPBody(mail.Header(part.Header), partBody)
			if strings.TrimSpace(text) != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n")
	}
	if strings.HasPrefix(strings.ToLower(mediaType), "text/") || mediaType == "" {
		return string(decoded)
	}
	return string(decoded)
}

func decodeICloudIMAPTransfer(encoding string, body []byte) []byte {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "quoted-printable":
		decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
		if err == nil {
			return decoded
		}
	case "base64":
		decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(body)))
		if err == nil {
			return decoded
		}
	}
	return body
}

func sortMessagesByReceivedAt(messages []ICloudSyncedMessage) {
	for i := 1; i < len(messages); i++ {
		for j := i; j > 0 && messages[j].ReceivedAt.After(messages[j-1].ReceivedAt); j-- {
			messages[j], messages[j-1] = messages[j-1], messages[j]
		}
	}
}
