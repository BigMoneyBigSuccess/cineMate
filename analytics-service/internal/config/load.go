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
	if value := strings.TrimSpace(os.Getenv("ANALYTICS_GRPC_ADDR")); value != "" {
		cfg.GRPC.Addr = value
	}
	if value := strings.TrimSpace(os.Getenv("ANALYTICS_DATABASE_URL")); value != "" {
		cfg.Postgres.URL = value
	}
	if value := strings.TrimSpace(os.Getenv("ANALYTICS_MOVIE_COLLECTION_ADDR")); value != "" {
		cfg.MovieCollection.Addr = value
	}
	if value := strings.TrimSpace(os.Getenv("ANALYTICS_MOVIE_COLLECTION_TIMEOUT")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse ANALYTICS_MOVIE_COLLECTION_TIMEOUT: %w", err)
		}
		cfg.MovieCollection.Timeout = parsed
	}
	if value := strings.TrimSpace(os.Getenv("ANALYTICS_RECOMMENDATION_DEFAULT_LIMIT")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse ANALYTICS_RECOMMENDATION_DEFAULT_LIMIT: %w", err)
		}
		cfg.Recommendation.DefaultLimit = parsed
	}
	if value := strings.TrimSpace(os.Getenv("ANALYTICS_RECOMMENDATION_CANDIDATE_POOL_SIZE")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse ANALYTICS_RECOMMENDATION_CANDIDATE_POOL_SIZE: %w", err)
		}
		cfg.Recommendation.CandidatePoolSize = parsed
	}
	if value := strings.TrimSpace(os.Getenv("ANALYTICS_SHUTDOWN_TIMEOUT")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse ANALYTICS_SHUTDOWN_TIMEOUT: %w", err)
		}
		cfg.ShutdownTimeout = parsed
	}

	return nil
}
