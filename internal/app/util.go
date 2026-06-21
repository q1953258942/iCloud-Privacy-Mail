package app

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"
)

func randomToken(bytesLen int) (string, error) {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(buf), "="), nil
}

func maskSecret(value string, keep int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if keep <= 0 || len(value) <= keep {
		return "********"
	}
	return "********" + value[len(value)-keep:]
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
