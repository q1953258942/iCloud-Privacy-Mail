package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ConfigPath        string `json:"-"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	DataPath          string `json:"data_path"`
	APIKey            string `json:"api_key"`
	PublicBaseURL     string `json:"public_base_url"`
	ICloudDefaultHost string `json:"icloud_default_host"`
	ICloudClientID    string `json:"icloud_client_id"`
}

func LoadConfig(path string) (Config, error) {
	cfg := Config{
		ConfigPath:        path,
		Host:              "127.0.0.1",
		Port:              8787,
		DataPath:          filepath.Join("data", "state.json"),
		APIKey:            strings.TrimSpace(os.Getenv("IPM_API_KEY")),
		PublicBaseURL:     strings.TrimRight(strings.TrimSpace(os.Getenv("IPM_PUBLIC_BASE_URL")), "/"),
		ICloudDefaultHost: "www.icloud.com.cn",
		ICloudClientID:    defaultAppleOAuthClientID,
	}
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return Config{}, err
	}
	var fromFile Config
	if err := json.Unmarshal(data, &fromFile); err != nil {
		return Config{}, err
	}
	if fromFile.Host != "" {
		cfg.Host = fromFile.Host
	}
	if fromFile.Port != 0 {
		cfg.Port = fromFile.Port
	}
	if fromFile.DataPath != "" {
		cfg.DataPath = fromFile.DataPath
	}
	if strings.TrimSpace(fromFile.APIKey) != "" {
		cfg.APIKey = strings.TrimSpace(fromFile.APIKey)
	}
	if strings.TrimSpace(fromFile.PublicBaseURL) != "" {
		cfg.PublicBaseURL = strings.TrimRight(strings.TrimSpace(fromFile.PublicBaseURL), "/")
	}
	if strings.TrimSpace(fromFile.ICloudDefaultHost) != "" {
		cfg.ICloudDefaultHost = strings.TrimSpace(fromFile.ICloudDefaultHost)
	}
	if strings.TrimSpace(fromFile.ICloudClientID) != "" {
		cfg.ICloudClientID = strings.TrimSpace(fromFile.ICloudClientID)
	}
	return cfg, nil
}
