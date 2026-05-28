package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

func Load(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := overrideFromEnv(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func overrideFromEnv(cfg *Config) error {
	if v := os.Getenv("API_GATEWAY_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("API_GATEWAY_PORT"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("parse API_GATEWAY_PORT: %w", err)
		}
		cfg.Server.Port = port
	}
	if v := os.Getenv("API_GATEWAY_AUTH_HOST"); v != "" {
		cfg.Auth.Host = v
	}
	if v := os.Getenv("API_GATEWAY_AUTH_PORT"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("parse API_GATEWAY_AUTH_PORT: %w", err)
		}
		cfg.Auth.Port = port
	}
	if v := os.Getenv("API_GATEWAY_MOVIES_HOST"); v != "" {
		cfg.Movies.Host = v
	}
	if v := os.Getenv("API_GATEWAY_MOVIES_PORT"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("parse API_GATEWAY_MOVIES_PORT: %w", err)
		}
		cfg.Movies.Port = port
	}
	if v := os.Getenv("API_GATEWAY_SOCIAL_HOST"); v != "" {
		cfg.Social.Host = v
	}
	if v := os.Getenv("API_GATEWAY_SOCIAL_PORT"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("parse API_GATEWAY_SOCIAL_PORT: %w", err)
		}
		cfg.Social.Port = port
	}
	return nil
}
