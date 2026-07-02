package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVersionIsNewer(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{current: "2026.07.01", latest: "2026.07.02", want: true},
		{current: "v1.2.3", latest: "v1.2.3", want: false},
		{current: "2026.07.02", latest: "v2026.7.2", want: false},
		{current: "v1.2.4", latest: "v1.2.3", want: false},
		{current: "dev", latest: "2026.07.02", want: true},
		{current: "2026.07.02", latest: "", want: false},
	}
	for _, tt := range tests {
		if got := versionIsNewer(tt.current, tt.latest); got != tt.want {
			t.Fatalf("versionIsNewer(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}

func TestSelectManifestAsset(t *testing.T) {
	assets := []updateManifestAsset{
		{Name: "panel_windows_amd64.exe", OS: "windows", Arch: "amd64", URL: "https://example.invalid/win"},
		{Name: "panel_linux_amd64.tar.gz", OS: "linux", Arch: "amd64", URL: "https://example.invalid/archive"},
		{Name: "panel_linux_amd64", OS: "linux", Arch: "amd64", URL: "https://example.invalid/linux"},
	}
	got, ok := selectManifestAsset(assets, "linux", "amd64", "")
	if !ok || got.Name != "panel_linux_amd64" {
		t.Fatalf("selected asset = %+v ok=%v, want linux amd64", got, ok)
	}
	got, ok = selectManifestAsset(assets, "linux", "amd64", "panel_windows_amd64.exe")
	if !ok || got.Name != "panel_windows_amd64.exe" {
		t.Fatalf("preferred asset = %+v ok=%v, want explicit preferred", got, ok)
	}
}

func TestFetchGitHubReleaseMissingFallsBackToDefaultBranchCommit(t *testing.T) {
	const latestSHA = "76acb88aabbccddeeff0011223344556677889900"
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/repos/q1953258942/iCloud-Privacy-Mail/releases/latest":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found","status":"404"}`))
		case "/repos/q1953258942/iCloud-Privacy-Mail":
			_, _ = w.Write([]byte(`{"default_branch":"master"}`))
		case "/repos/q1953258942/iCloud-Privacy-Mail/commits/master":
			_, _ = w.Write([]byte(`{"sha":"` + latestSHA + `","commit":{"message":"最新提交","committer":{"date":"2026-07-02T03:00:00Z"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	oldBaseURL := updateGitHubAPIBaseURL
	oldCommit := AppCommit
	updateGitHubAPIBaseURL = server.URL
	AppCommit = "76acb88"
	defer func() {
		updateGitHubAPIBaseURL = oldBaseURL
		AppCommit = oldCommit
	}()

	s := &Server{cfg: Config{
		UpdateEnabled:    true,
		UpdateRepository: "q1953258942/iCloud-Privacy-Mail",
	}}
	candidate, err := s.fetchGitHubReleaseUpdateCandidate(context.Background(), publicUpdateStatus{
		Enabled:   true,
		Current:   currentVersionInfo(),
		CheckedAt: formatTime(time.Now()),
	})
	if err != nil {
		t.Fatalf("fetchGitHubReleaseUpdateCandidate returned error: %v", err)
	}
	if candidate.Status.Error != "" {
		t.Fatalf("status error = %q, want empty", candidate.Status.Error)
	}
	if candidate.Status.UpdateAvailable {
		t.Fatalf("update_available = true, want false when current commit matches default branch")
	}
	if !strings.Contains(candidate.Status.LatestName, "76acb88") {
		t.Fatalf("latest_name = %q, want short commit", candidate.Status.LatestName)
	}
	wantRequests := strings.Join([]string{
		"/repos/q1953258942/iCloud-Privacy-Mail/releases/latest",
		"/repos/q1953258942/iCloud-Privacy-Mail",
		"/repos/q1953258942/iCloud-Privacy-Mail/commits/master",
	}, ",")
	if got := strings.Join(requests, ","); got != wantRequests {
		t.Fatalf("requests = %s, want %s", got, wantRequests)
	}
}
