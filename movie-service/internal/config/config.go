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
	ShutdownTimeout time.Duration  `yaml:"shutdown_timeout"`
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
