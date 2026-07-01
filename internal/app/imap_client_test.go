package app

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestICloudIMAPMessagesByMailboxMatchesRecipientAlias(t *testing.T) {
	receivedAt := time.Date(2026, 7, 1, 5, 2, 50, 0, time.UTC)
	mailboxes := []Mailbox{
		{ID: "mbx_match", Email: "alias-one@icloud.com"},
		{ID: "mbx_other", Email: "alias-two@icloud.com"},
	}
	raw := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: alias-one@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Date: " + receivedAt.Format(time.RFC1123Z) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Enter this temporary verification code to continue: 246810\r\n"

	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "42", Raw: []byte(raw)}}, mailboxes, receivedAt.Add(-time.Minute), "ChatGPT")
	messages := got["mbx_match"]
	if len(messages) != 1 {
		t.Fatalf("matched messages = %d, want 1; got=%+v", len(messages), got)
	}
	if code := extractOTP(messages[0].Subject + "\n" + messages[0].Body); code != "246810" {
		t.Fatalf("code = %q, want 246810; message=%+v", code, messages[0])
	}
	if messages[0].RemoteID != "imap:42" || messages[0].UID != "42" {
		t.Fatalf("remote id/uid = %q/%q, want imap:42/42", messages[0].RemoteID, messages[0].UID)
	}
	if len(got["mbx_other"]) != 0 {
		t.Fatalf("wrong alias received messages: %+v", got["mbx_other"])
	}
}

func TestICloudIMAPMessagesByMailboxMatchesMultipleRecipientAliases(t *testing.T) {
	firstAt := time.Date(2026, 7, 1, 5, 2, 50, 0, time.UTC)
	secondAt := firstAt.Add(20 * time.Second)
	mailboxes := []Mailbox{
		{ID: "mbx_one", Email: "alias-one@icloud.com"},
		{ID: "mbx_two", Email: "alias-two@icloud.com"},
	}
	rawOne := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: alias-one@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Date: " + firstAt.Format(time.RFC1123Z) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Enter this temporary verification code to continue: 111111\r\n"
	rawTwo := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: alias-two@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Date: " + secondAt.Format(time.RFC1123Z) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Enter this temporary verification code to continue: 222222\r\n"

	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{
		{UID: "101", Raw: []byte(rawOne)},
		{UID: "102", Raw: []byte(rawTwo)},
	}, mailboxes, time.Time{}, "ChatGPT")

	if messages := got["mbx_one"]; len(messages) != 1 || extractOTP(messages[0].Subject+"\n"+messages[0].Body) != "111111" {
		t.Fatalf("mbx_one messages = %+v, want one message with code 111111", messages)
	}
	if messages := got["mbx_two"]; len(messages) != 1 || extractOTP(messages[0].Subject+"\n"+messages[0].Body) != "222222" {
		t.Fatalf("mbx_two messages = %+v, want one message with code 222222", messages)
	}
}

func TestICloudIMAPMessagesByMailboxIgnoresIMAPLoginEmail(t *testing.T) {
	receivedAt := time.Date(2026, 7, 1, 5, 2, 50, 0, time.UTC)
	mailboxes := []Mailbox{
		{ID: "mbx_login", Email: "owner@icloud.com"},
		{ID: "mbx_alias", Email: "alias-one@icloud.com"},
	}
	raw := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: alias-one@icloud.com\r\n" +
		"Delivered-To: owner@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Date: " + receivedAt.Format(time.RFC1123Z) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Enter this temporary verification code to continue: 333333\r\n"

	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "103", Raw: []byte(raw)}}, mailboxes, time.Time{}, "ChatGPT", "owner@icloud.com")
	if messages := got["mbx_alias"]; len(messages) != 1 || extractOTP(messages[0].Subject+"\n"+messages[0].Body) != "333333" {
		t.Fatalf("alias messages = %+v, want one message with code 333333", messages)
	}
	if len(got["mbx_login"]) != 0 {
		t.Fatalf("login mailbox should be ignored, got=%+v", got["mbx_login"])
	}
}

func TestICloudIMAPMessagesByMailboxIgnoresWrongAlias(t *testing.T) {
	mailboxes := []Mailbox{{ID: "mbx_target", Email: "target@icloud.com"}}
	raw := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: someone-else@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Date: Wed, 01 Jul 2026 05:02:50 +0000\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Enter this temporary verification code to continue: 135790\r\n"

	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "51", Raw: []byte(raw)}}, mailboxes, time.Time{}, "ChatGPT")
	if len(got["mbx_target"]) != 0 {
		t.Fatalf("wrong alias should not match, got=%+v", got["mbx_target"])
	}
}

func TestICloudIMAPMessagesByMailboxIgnoresAliasMentionedOnlyInBody(t *testing.T) {
	mailboxes := []Mailbox{{ID: "mbx_target", Email: "target@icloud.com"}}
	raw := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: someone-else@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Date: Wed, 01 Jul 2026 05:02:50 +0000\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Enter this temporary verification code to continue: 975310\r\n" +
		"This message mentions target@icloud.com in the body only.\r\n"

	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "52", Raw: []byte(raw)}}, mailboxes, time.Time{}, "ChatGPT")
	if len(got["mbx_target"]) != 0 {
		t.Fatalf("alias mentioned only in body should not match, got=%+v", got["mbx_target"])
	}
}

func TestIMAPLineHasExistsEvent(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{line: "* 123 EXISTS", want: true},
		{line: "* 1 RECENT", want: false},
		{line: "A001 OK IDLE completed", want: false},
		{line: "* 123 FETCH (UID 9)", want: false},
	}
	for _, tc := range cases {
		if got := imapLineHasExistsEvent(tc.line); got != tc.want {
			t.Fatalf("imapLineHasExistsEvent(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

func TestIMAPSearchCommandUsesUIDCursorWhenAvailable(t *testing.T) {
	command := imapSearchCommand(LoginState{}, []Mailbox{
		{Email: "one@icloud.com", LastSyncUID: "42"},
		{Email: "two@icloud.com", LastSyncUID: "imap:50"},
	}, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	if command != "UID SEARCH UID 43:*" {
		t.Fatalf("imapSearchCommand with cursors = %q, want UID SEARCH UID 43:*", command)
	}
}

func TestIMAPSearchCommandPrefersAccountCursor(t *testing.T) {
	command := imapSearchCommand(LoginState{IMAPLastSyncUID: "100"}, []Mailbox{
		{Email: "one@icloud.com"},
		{Email: "two@icloud.com", LastSyncUID: "42"},
	}, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	if command != "UID SEARCH UID 101:*" {
		t.Fatalf("imapSearchCommand account cursor = %q, want UID SEARCH UID 101:*", command)
	}
}

func TestIMAPSelectUIDNextLastUID(t *testing.T) {
	lines := []string{
		"* 652 EXISTS",
		"* OK [UIDVALIDITY 1] UIDs valid",
		"* OK [UIDNEXT 88291] Predicted next UID",
		"A002 OK [READ-WRITE] SELECT completed",
	}
	if got := imapSelectLastUID(lines); got != 88290 {
		t.Fatalf("imapSelectLastUID() = %d, want 88290", got)
	}
}

func TestIMAPSearchCommandFallsBackToSinceWhenCursorMissing(t *testing.T) {
	after := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	command := imapSearchCommand(LoginState{}, []Mailbox{
		{Email: "one@icloud.com", LastSyncUID: "42"},
		{Email: "two@icloud.com"},
	}, after)
	if command != "UID SEARCH SINCE 1-Jul-2026" {
		t.Fatalf("imapSearchCommand without all cursors = %q, want SINCE fallback", command)
	}
}

func TestICloudIMAPDialerUsesFallbackResolver(t *testing.T) {
	dialer := newICloudIMAPDialer("imap.mail.me.com")
	if dialer.NetDialer == nil {
		t.Fatal("imap dialer NetDialer is nil")
	}
	if dialer.NetDialer.Resolver == nil {
		t.Fatal("imap dialer Resolver is nil, want public DNS fallback")
	}
	if dialer.NetDialer.Timeout != 15*time.Second {
		t.Fatalf("imap dialer timeout = %s, want 15s", dialer.NetDialer.Timeout)
	}
	if dialer.Config == nil || dialer.Config.ServerName != "imap.mail.me.com" {
		t.Fatalf("imap dialer TLS config = %+v", dialer.Config)
	}
}

func TestDNSFallbackNetworksPreferTCPBeforeUDP(t *testing.T) {
	got := dnsFallbackNetworks("udp6")
	want := []string{"tcp", "udp"}
	if len(got) != len(want) {
		t.Fatalf("dnsFallbackNetworks length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dnsFallbackNetworks(%q)[%d] = %q, want %q", "udp6", i, got[i], want[i])
		}
	}
}

func TestDNSParseAResponse(t *testing.T) {
	const id uint16 = 0x1234
	query, err := dnsBuildAQuery("imap.mail.me.com", id)
	if err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(response[0:2], id)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, query[12:]...)
	response = append(response, 0xc0, 0x0c)
	response = binary.BigEndian.AppendUint16(response, 1)
	response = binary.BigEndian.AppendUint16(response, 1)
	response = binary.BigEndian.AppendUint32(response, 60)
	response = binary.BigEndian.AppendUint16(response, 4)
	response = append(response, 17, 57, 152, 32)

	ips, err := dnsParseAResponse(response, id)
	if err != nil {
		t.Fatal(err)
	}
	want := net.IPv4(17, 57, 152, 32).String()
	if len(ips) != 1 || ips[0].String() != want {
		t.Fatalf("dnsParseAResponse = %v, want %s", ips, want)
	}
}

func TestAppendUniqueIPv4(t *testing.T) {
	got := appendUniqueIPv4(
		[]net.IP{net.IPv4(17, 57, 152, 32), net.ParseIP("2001:db8::1")},
		net.IPv4(17, 57, 152, 32),
		net.IPv4(17, 57, 152, 35),
	)
	if len(got) != 2 {
		t.Fatalf("appendUniqueIPv4 length = %d, want 2: %v", len(got), got)
	}
	if got[0].String() != "17.57.152.32" || got[1].String() != "17.57.152.35" {
		t.Fatalf("appendUniqueIPv4 order = %v", got)
	}
}
