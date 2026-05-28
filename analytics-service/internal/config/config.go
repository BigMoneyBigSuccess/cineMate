package config

import (
	"errors"
	"fmt"
	"time"
)

const DefaultPath = "configs/config.local.yaml"

type Config struct {
	GRPC            GRPCConfig           `yaml:"grpc"`
	Postgres        PostgresConfig       `yaml:"postgres"`
	MovieCollection MovieCatalogConfig   `yaml:"movie_collection"`
	Recommendation  RecommendationConfig `yaml:"recommendation"`
	OpenRouter      OpenRouterConfig     `yaml:"open_router"`
	ShutdownTimeout time.Duration        `yaml:"shutdown_timeout"`
}

type GRPCConfig struct {
	Addr string `yaml:"addr"`
}

type PostgresConfig struct {
	URL string `yaml:"url"`
}

type MovieCatalogConfig struct {
	Addr    string        `yaml:"addr"`
	Timeout time.Duration `yaml:"timeout"`
}

type RecommendationConfig struct {
	DefaultLimit      int `yaml:"default_limit"`
	CandidatePoolSize int `yaml:"candidate_pool_size"`
}

type OpenRouterConfig struct {
	APIKey  string        `yaml:"api_key"`
	Model   string        `yaml:"model"`
	Timeout time.Duration `yaml:"timeout"`
}

func Default() Config {
	return Config{
		GRPC: GRPCConfig{
			Addr: ":50054",
		},
		MovieCollection: MovieCatalogConfig{
			Addr:    "localhost:50052",
			Timeout: 3 * time.Second,
		},
		Recommendation: RecommendationConfig{
			DefaultLimit:      10,
			CandidatePoolSize: 100,
		},
		OpenRouter: OpenRouterConfig{
			Model:   "openrouter/free",
			Timeout: 60 * time.Second,
		},
		ShutdownTimeout: 10 * time.Second,
	}
}

func (c Config) Validate() error {
	switch {
	case c.GRPC.Addr == "":
		return errors.New("grpc.addr is required")
	case c.Postgres.URL == "":
		return errors.New("postgres.url is required")
	case c.MovieCollection.Addr == "":
		return errors.New("movie_collection.addr is required")
	case c.MovieCollection.Timeout <= 0:
		return errors.New("movie_collection.timeout must be greater than zero")
	case c.Recommendation.DefaultLimit <= 0:
		return errors.New("recommendation.default_limit must be greater than zero")
	case c.Recommendation.CandidatePoolSize <= 0:
		return errors.New("recommendation.candidate_pool_size must be greater than zero")
	case c.Recommendation.CandidatePoolSize < c.Recommendation.DefaultLimit:
		return errors.New("recommendation.candidate_pool_size must be greater than or equal to recommendation.default_limit")
	case c.ShutdownTimeout <= 0:
		return errors.New("shutdown_timeout must be greater than zero")
	default:
		return nil
	}
}

func (c Config) String() string {
	return fmt.Sprintf(
		"grpc=%s postgres=%t movie_collection=%s recommendation_default_limit=%d candidate_pool_size=%d shutdown_timeout=%s",
		c.GRPC.Addr,
		c.Postgres.URL != "",
		c.MovieCollection.Addr,
		c.Recommendation.DefaultLimit,
		c.Recommendation.CandidatePoolSize,
		c.ShutdownTimeout,
	)
}
