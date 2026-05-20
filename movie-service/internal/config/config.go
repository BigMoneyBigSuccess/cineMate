package config

import (
	"errors"
	"fmt"
	"time"
)

const DefaultPath = "configs/config.local.yaml"

type Config struct {
	GRPC            GRPCConfig     `yaml:"grpc"`
	Postgres        PostgresConfig `yaml:"postgres"`
	Redis           RedisConfig    `yaml:"redis"`
	Cache           CacheConfig    `yaml:"cache"`
	Syncer          SyncerConfig   `yaml:"syncer"`
	ShutdownTimeout time.Duration  `yaml:"shutdown_timeout"`
}

type SyncerConfig struct {
	Enabled            bool   `yaml:"enabled"`
	APIKey             string `yaml:"api_key"`
	BaseURL            string `yaml:"base_url"`
	DailyRequestBudget int    `yaml:"daily_request_budget"`
	FetchDescription   bool   `yaml:"fetch_description"`
}

type GRPCConfig struct {
	Addr string `yaml:"addr"`
}

type PostgresConfig struct {
	URL string `yaml:"url"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type CacheConfig struct {
	MovieTTL     time.Duration `yaml:"movie_ttl"`
	MovieListTTL time.Duration `yaml:"movie_list_ttl"`
}

func Default() Config {
	return Config{
		GRPC: GRPCConfig{
			Addr: ":8080",
		},
		Cache: CacheConfig{
			MovieTTL:     30 * time.Minute,
			MovieListTTL: 2 * time.Minute,
		},
		Syncer: SyncerConfig{
			BaseURL:            "https://kinopoiskapiunofficial.tech",
			DailyRequestBudget: 500,
			FetchDescription:   true,
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
	case c.Cache.MovieTTL <= 0:
		return errors.New("cache.movie_ttl must be greater than zero")
	case c.Cache.MovieListTTL <= 0:
		return errors.New("cache.movie_list_ttl must be greater than zero")
	case c.ShutdownTimeout <= 0:
		return errors.New("shutdown_timeout must be greater than zero")
	case c.Redis.DB < 0:
		return errors.New("redis.db must be non-negative")
	case c.Syncer.Enabled && c.Syncer.APIKey == "":
		return errors.New("syncer.api_key is required when syncer is enabled")
	case c.Syncer.Enabled && c.Syncer.DailyRequestBudget <= 0:
		return errors.New("syncer.daily_request_budget must be positive when syncer is enabled")
	case c.Syncer.Enabled && c.Syncer.BaseURL == "":
		return errors.New("syncer.base_url is required when syncer is enabled")
	default:
		return nil
	}
}

func (c Config) String() string {
	return fmt.Sprintf(
		"grpc=%s postgres=%t redis=%t redis_db=%d movie_cache_ttl=%s movie_list_ttl=%s shutdown_timeout=%s",
		c.GRPC.Addr,
		c.Postgres.URL != "",
		c.Redis.Addr != "",
		c.Redis.DB,
		c.Cache.MovieTTL,
		c.Cache.MovieListTTL,
		c.ShutdownTimeout,
	)
}
