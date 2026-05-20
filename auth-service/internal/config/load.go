package config

import (
	"fmt"
	"os"
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

	if databaseURL := os.Getenv("DATABASE_URL"); databaseURL != "" {
		cfg.Postgres.URL = databaseURL
	}

	if grpcAddr := os.Getenv("GRPC_ADDR"); grpcAddr != "" {
		cfg.GRPC.Addr = grpcAddr
	}

	if shutdownTimeout := os.Getenv("SHUTDOWN_TIMEOUT"); shutdownTimeout != "" {
		duration, err := time.ParseDuration(shutdownTimeout)
		if err != nil {
			return Config{}, fmt.Errorf("parse shutdown timeout: %w", err)
		}
		cfg.ShutdownTimeout = duration
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
