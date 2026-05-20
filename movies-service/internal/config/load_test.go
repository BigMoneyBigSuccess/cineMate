package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadReadsYAMLConfig(t *testing.T) {
	clearMovieCollectionEnv(t)

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configBody := []byte(`
grpc:
  addr: ":9090"
postgres:
  url: "postgres://user:pass@localhost:5432/movies?sslmode=disable"
redis:
  addr: "localhost:6380"
  password: "secret"
  db: 2
cache:
  movie_ttl: 45m
  movie_list_ttl: 3m
shutdown_timeout: 15s
`)

	if err := os.WriteFile(configPath, configBody, 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.GRPC.Addr != ":9090" {
		t.Fatalf("unexpected grpc addr: %s", cfg.GRPC.Addr)
	}
	if cfg.Postgres.URL != "postgres://user:pass@localhost:5432/movies?sslmode=disable" {
		t.Fatalf("unexpected postgres url: %s", cfg.Postgres.URL)
	}
	if cfg.Redis.Addr != "localhost:6380" {
		t.Fatalf("unexpected redis addr: %s", cfg.Redis.Addr)
	}
	if cfg.Redis.Password != "secret" {
		t.Fatalf("unexpected redis password: %s", cfg.Redis.Password)
	}
	if cfg.Redis.DB != 2 {
		t.Fatalf("unexpected redis db: %d", cfg.Redis.DB)
	}
	if cfg.Cache.MovieTTL != 45*time.Minute {
		t.Fatalf("unexpected movie ttl: %s", cfg.Cache.MovieTTL)
	}
	if cfg.Cache.MovieListTTL != 3*time.Minute {
		t.Fatalf("unexpected movie list ttl: %s", cfg.Cache.MovieListTTL)
	}
	if cfg.ShutdownTimeout != 15*time.Second {
		t.Fatalf("unexpected shutdown timeout: %s", cfg.ShutdownTimeout)
	}
}

func TestLoadAppliesEnvOverrides(t *testing.T) {
	clearMovieCollectionEnv(t)

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configBody := []byte(`
grpc:
  addr: ":9090"
postgres:
  url: "postgres://user:pass@localhost:5432/movies?sslmode=disable"
redis:
  addr: "localhost:6380"
  password: ""
  db: 2
cache:
  movie_ttl: 45m
  movie_list_ttl: 3m
shutdown_timeout: 15s
`)

	if err := os.WriteFile(configPath, configBody, 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	t.Setenv("MOVIE_COLLECTION_GRPC_ADDR", ":9191")
	t.Setenv("MOVIE_COLLECTION_DATABASE_URL", "postgres://override:override@db:5432/override?sslmode=disable")
	t.Setenv("MOVIE_COLLECTION_REDIS_ADDR", "redis:6379")
	t.Setenv("MOVIE_COLLECTION_REDIS_PASSWORD", "override-secret")
	t.Setenv("MOVIE_COLLECTION_REDIS_DB", "4")
	t.Setenv("MOVIE_COLLECTION_MOVIE_CACHE_TTL", "50m")
	t.Setenv("MOVIE_COLLECTION_MOVIE_LIST_CACHE_TTL", "4m")
	t.Setenv("MOVIE_COLLECTION_SHUTDOWN_TIMEOUT", "20s")

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.GRPC.Addr != ":9191" {
		t.Fatalf("unexpected grpc addr: %s", cfg.GRPC.Addr)
	}
	if cfg.Postgres.URL != "postgres://override:override@db:5432/override?sslmode=disable" {
		t.Fatalf("unexpected postgres url: %s", cfg.Postgres.URL)
	}
	if cfg.Redis.Addr != "redis:6379" {
		t.Fatalf("unexpected redis addr: %s", cfg.Redis.Addr)
	}
	if cfg.Redis.Password != "override-secret" {
		t.Fatalf("unexpected redis password: %s", cfg.Redis.Password)
	}
	if cfg.Redis.DB != 4 {
		t.Fatalf("unexpected redis db: %d", cfg.Redis.DB)
	}
	if cfg.Cache.MovieTTL != 50*time.Minute {
		t.Fatalf("unexpected movie ttl: %s", cfg.Cache.MovieTTL)
	}
	if cfg.Cache.MovieListTTL != 4*time.Minute {
		t.Fatalf("unexpected movie list ttl: %s", cfg.Cache.MovieListTTL)
	}
	if cfg.ShutdownTimeout != 20*time.Second {
		t.Fatalf("unexpected shutdown timeout: %s", cfg.ShutdownTimeout)
	}
}

func clearMovieCollectionEnv(t *testing.T) {
	t.Helper()

	keys := []string{
		"MOVIE_COLLECTION_GRPC_ADDR",
		"MOVIE_COLLECTION_DATABASE_URL",
		"MOVIE_COLLECTION_REDIS_ADDR",
		"MOVIE_COLLECTION_REDIS_PASSWORD",
		"MOVIE_COLLECTION_REDIS_DB",
		"MOVIE_COLLECTION_MOVIE_CACHE_TTL",
		"MOVIE_COLLECTION_MOVIE_LIST_CACHE_TTL",
		"MOVIE_COLLECTION_SHUTDOWN_TIMEOUT",
	}

	original := make(map[string]*string, len(keys))
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			copied := value
			original[key] = &copied
		} else {
			original[key] = nil
		}

		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset env %s: %v", key, err)
		}
	}

	t.Cleanup(func() {
		for _, key := range keys {
			value := original[key]
			if value == nil {
				_ = os.Unsetenv(key)
				continue
			}
			_ = os.Setenv(key, *value)
		}
	})
}
