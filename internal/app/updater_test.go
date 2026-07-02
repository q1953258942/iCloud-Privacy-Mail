package app

import "testing"

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
