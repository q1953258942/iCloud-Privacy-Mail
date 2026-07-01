package app

import (
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
