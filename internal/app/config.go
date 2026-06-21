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
	AdminKey          string `json:"admin_key"`
	PublicBaseURL     string `json:"public_base_url"`
	BitBrowserAPI     string `json:"bit_browser_api"`
	BitBrowserID      string `json:"bit_browser_id"`
	ICloudLoginURL    string `json:"icloud_login_url"`
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
		AdminKey:          strings.TrimSpace(os.Getenv("IPM_ADMIN_KEY")),
		PublicBaseURL:     strings.TrimRight(strings.TrimSpace(os.Getenv("IPM_PUBLIC_BASE_URL")), "/"),
		BitBrowserAPI:     "http://127.0.0.1:54345",
		BitBrowserID:      strings.TrimSpace(os.Getenv("IPM_BIT_BROWSER_ID")),
		ICloudLoginURL:    "https://www.icloud.com.cn/icloudplus/",
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
	if strings.TrimSpace(fromFile.AdminKey) != "" {
		cfg.AdminKey = strings.TrimSpace(fromFile.AdminKey)
	}
	if strings.TrimSpace(fromFile.PublicBaseURL) != "" {
		cfg.PublicBaseURL = strings.TrimRight(strings.TrimSpace(fromFile.PublicBaseURL), "/")
	}
	if strings.TrimSpace(fromFile.BitBrowserAPI) != "" {
		cfg.BitBrowserAPI = strings.TrimRight(strings.TrimSpace(fromFile.BitBrowserAPI), "/")
	}
	if strings.TrimSpace(fromFile.BitBrowserID) != "" {
		cfg.BitBrowserID = strings.TrimSpace(fromFile.BitBrowserID)
	}
	if strings.TrimSpace(fromFile.ICloudLoginURL) != "" {
		cfg.ICloudLoginURL = strings.TrimSpace(fromFile.ICloudLoginURL)
	}
	if strings.TrimSpace(fromFile.ICloudDefaultHost) != "" {
		cfg.ICloudDefaultHost = strings.TrimSpace(fromFile.ICloudDefaultHost)
	}
	if strings.TrimSpace(fromFile.ICloudClientID) != "" {
		cfg.ICloudClientID = strings.TrimSpace(fromFile.ICloudClientID)
	}
	return cfg, nil
}

func SaveConfigDataPath(path, dataPath string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errCode("config_path_missing", "当前启动命令没有配置文件路径，无法持久化运行配置", false)
	}
	values := map[string]any{}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		if err := json.Unmarshal(data, &values); err != nil {
			return err
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	values["data_path"] = dataPath
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
