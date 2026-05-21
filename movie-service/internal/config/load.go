package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func Load(path string) (Config, error) {
	cfg := Default()
	resolvedPath := strings.TrimSpace(path)
	if resolvedPath == "" {
		resolvedPath = DefaultPath
	}

	if err := loadFromFile(resolvedPath, &cfg); err != nil {
		return Config{}, err
	}

	if err := overrideFromEnv(&cfg); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func loadFromFile(path string, cfg *Config) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config file %s: %w", path, err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)

	if err := decoder.Decode(cfg); err != nil {
		return fmt.Errorf("decode config file %s: %w", path, err)
	}

	return nil
}

func overrideFromEnv(cfg *Config) error {
	if value := strings.TrimSpace(os.Getenv("MOVIE_SERVICE_GRPC_ADDR")); value != "" {
		cfg.GRPC.Addr = value
	}
	if value := strings.TrimSpace(os.Getenv("MOVIE_SERVICE_DATABASE_URL")); value != "" {
		cfg.Postgres.URL = value
	}
	if value := strings.TrimSpace(os.Getenv("MOVIE_SERVICE_REDIS_ADDR")); value != "" {
		cfg.Redis.Addr = value
	}
	if value, ok := os.LookupEnv("MOVIE_SERVICE_REDIS_PASSWORD"); ok {
		cfg.Redis.Password = value
	}
	if value := strings.TrimSpace(os.Getenv("MOVIE_SERVICE_REDIS_DB")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse MOVIE_SERVICE_REDIS_DB: %w", err)
		}
		cfg.Redis.DB = parsed
	}
	if value := strings.TrimSpace(os.Getenv("MOVIE_SERVICE_MOVIE_CACHE_TTL")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse MOVIE_SERVICE_MOVIE_CACHE_TTL: %w", err)
		}
		cfg.Cache.MovieTTL = parsed
	}
	if value := strings.TrimSpace(os.Getenv("MOVIE_SERVICE_MOVIE_LIST_CACHE_TTL")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse MOVIE_SERVICE_MOVIE_LIST_CACHE_TTL: %w", err)
		}
		cfg.Cache.MovieListTTL = parsed
	}
	if value := strings.TrimSpace(os.Getenv("MOVIE_SERVICE_SHUTDOWN_TIMEOUT")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse MOVIE_SERVICE_SHUTDOWN_TIMEOUT: %w", err)
		}
		cfg.ShutdownTimeout = parsed
	}
	if value := strings.TrimSpace(os.Getenv("MOVIE_SERVICE_SYNCER_API_KEY")); value != "" {
		cfg.Syncer.APIKey = value
	}
	if value := strings.TrimSpace(os.Getenv("MOVIE_SERVICE_SYNCER_ENABLED")); value != "" {
		cfg.Syncer.Enabled = value == "true" || value == "1"
	}
	if value := strings.TrimSpace(os.Getenv("MOVIE_SERVICE_SYNCER_BASE_URL")); value != "" {
		cfg.Syncer.BaseURL = value
	}
	if value := strings.TrimSpace(os.Getenv("MOVIE_SERVICE_SYNCER_DAILY_REQUEST_BUDGET")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse MOVIE_SERVICE_SYNCER_DAILY_REQUEST_BUDGET: %w", err)
		}
		cfg.Syncer.DailyRequestBudget = parsed
	}

	return nil
}
