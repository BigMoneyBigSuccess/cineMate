package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/goccy/go-yaml"
)

func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}

	if v := os.Getenv("AUTH_DATABASE_URL"); v != "" {
		cfg.Postgres.URL = v
	}
	if v := os.Getenv("AUTH_GRPC_ADDR"); v != "" {
		cfg.GRPC.Addr = v
	}
	if v := os.Getenv("AUTH_SOCIAL_HOST"); v != "" {
		cfg.Social.Host = v
	}
	if v := os.Getenv("AUTH_SOCIAL_PORT"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("parse AUTH_SOCIAL_PORT: %w", err)
		}
		cfg.Social.Port = port
	}
	if v := os.Getenv("AUTH_SHUTDOWN_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("parse AUTH_SHUTDOWN_TIMEOUT: %w", err)
		}
		cfg.ShutdownTimeout = d
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
