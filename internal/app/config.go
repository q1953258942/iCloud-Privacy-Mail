package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	DataPath string `json:"data_path"`
	APIKey   string `json:"api_key"`
}

func LoadConfig(path string) (Config, error) {
	cfg := Config{
		Host:     "127.0.0.1",
		Port:     8787,
		DataPath: filepath.Join("data", "state.json"),
		APIKey:   strings.TrimSpace(os.Getenv("IPM_API_KEY")),
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
	return cfg, nil
}
