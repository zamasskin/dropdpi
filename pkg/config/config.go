package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	ServerAddress string `json:"server_address"` // Address of the remote server (e.g. "1.2.3.4:8443")
	ServerListen  string `json:"server_listen"`  // Address to listen on server side (e.g. ":8443")
	ClientListen  string `json:"client_listen"`  // Address to listen on client side (e.g. "127.0.0.1:1080")
	Key           string `json:"key"`            // 32-byte encryption key
	FakePage      string `json:"fake_page"`      // Path to HTML file to serve on non-proxy requests
	EnableTLS     bool   `json:"enable_tls"`     // Enable TLS on server (default false)
}

func LoadConfig(path string) (*Config, error) {
	// 1. Defaults
	cfg := &Config{
		ServerAddress: "127.0.0.1:8443",
		ServerListen:  ":8443",
		ClientListen:  "127.0.0.1:1080",
		Key:           "0123456789abcdef0123456789abcdef",
		EnableTLS:     false,
	}

	// 2. Determine config file to load
	// Priority:
	// 1. Explicit path passed in argument (if not empty and exists)
	// 2. "config.json" in current directory
	// 3. "/etc/dropdpi/config.json"

	filesToCheck := []string{}
	if path != "" {
		filesToCheck = append(filesToCheck, path)
	}
	// Add defaults only if path wasn't explicitly provided or if we want fallback behavior.
	// Typically, if user provides -config, we only look there.
	// But if user provided "config.json" (default flag value), we might want to look elsewhere if it doesn't exist.
	// Let's assume 'path' is what came from flag.

	// If path is "config.json" (default) and it doesn't exist, we try /etc/dropdpi/config.json
	if path == "config.json" {
		filesToCheck = append(filesToCheck, "/etc/dropdpi/config.json")
	}

	var loadedFile string

	for _, p := range filesToCheck {
		file, err := os.Open(p)
		if err == nil {
			defer file.Close()
			decoder := json.NewDecoder(file)
			if err := decoder.Decode(cfg); err != nil {
				return nil, err
			}
			loadedFile = p
			break // Successfully loaded
		} else if !os.IsNotExist(err) {
			// If it's a permission error or something else, return error only if it was the explicitly requested file
			if p == path && path != "config.json" {
				return nil, err
			}
		}
	}

	if loadedFile != "" {
		// Can log here if we had logger, but pkg/config shouldn't log
	}

	// 3. Override with Environment Variables
	if v := os.Getenv("DROPDPI_SERVER_ADDRESS"); v != "" {
		cfg.ServerAddress = v
	}
	if v := os.Getenv("DROPDPI_SERVER_LISTEN"); v != "" {
		cfg.ServerListen = v
	}
	if v := os.Getenv("DROPDPI_CLIENT_LISTEN"); v != "" {
		cfg.ClientListen = v
	}
	if v := os.Getenv("DROPDPI_KEY"); v != "" {
		cfg.Key = v
	}
	if v := os.Getenv("DROPDPI_FAKE_PAGE"); v != "" {
		cfg.FakePage = v
	}
	if v := os.Getenv("DROPDPI_ENABLE_TLS"); v != "" {
		if v == "false" || v == "0" {
			cfg.EnableTLS = false
		} else {
			cfg.EnableTLS = true
		}
	}

	return cfg, nil
}

func (c *Config) Save(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(c)
}
