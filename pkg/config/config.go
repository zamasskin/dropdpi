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
}

func LoadConfig(path string) (*Config, error) {
	// 1. Defaults
	cfg := &Config{
		ServerAddress: "127.0.0.1:8443",
		ServerListen:  ":8443",
		ClientListen:  "127.0.0.1:1080",
		Key:           "0123456789abcdef0123456789abcdef",
	}

	// 2. Load from file if exists
	// We ignore IsNotExist error to allow running with defaults/env vars only
	if path != "" {
		file, err := os.Open(path)
		if err == nil {
			defer file.Close()
			decoder := json.NewDecoder(file)
			if err := decoder.Decode(cfg); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			// If it's a permission error or something else, we return it
			return nil, err
		}
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
