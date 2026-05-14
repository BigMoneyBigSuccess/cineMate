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
	ShutdownTimeout time.Duration  `yaml:"shutdown_timeout"`
}

type GRPCConfig struct {
	Addr string `yaml:"addr"`
}

type PostgresConfig struct {
	URL string `yaml:"url"`
}

func Default() Config {
	return Config{
		GRPC: GRPCConfig{
			Addr: ":9090",
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
	case c.ShutdownTimeout <= 0:
		return errors.New("shutdown_timeout must be greater than zero")
	default:
		return nil
	}
}

func (c Config) String() string {
	return fmt.Sprintf("grpc=%s postgres=%t shutdown_timeout=%s", c.GRPC.Addr, c.Postgres.URL != "", c.ShutdownTimeout)
}
