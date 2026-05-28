package config

import (
	"testing"
	"time"
)

func validConfig() Config {
	return Config{
		GRPC:     GRPCConfig{Addr: ":50052"},
		Postgres: PostgresConfig{URL: "postgres://user:pass@localhost:5432/movies?sslmode=disable"},
		Redis:    RedisConfig{Addr: "localhost:6379", DB: 0},
		Cache: CacheConfig{
			MovieTTL:     30 * time.Minute,
			MovieListTTL: 2 * time.Minute,
		},
		ShutdownTimeout: 10 * time.Second,
	}
}

func TestConfigValidateValidConfig(t *testing.T) {
	t.Parallel()

	if err := validConfig().Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr bool
	}{
		{
			name:    "missing grpc addr",
			mutate:  func(c *Config) { c.GRPC.Addr = "" },
			wantErr: true,
		},
		{
			name:    "missing postgres url",
			mutate:  func(c *Config) { c.Postgres.URL = "" },
			wantErr: true,
		},
		{
			name:    "zero movie ttl",
			mutate:  func(c *Config) { c.Cache.MovieTTL = 0 },
			wantErr: true,
		},
		{
			name:    "negative movie ttl",
			mutate:  func(c *Config) { c.Cache.MovieTTL = -1 * time.Second },
			wantErr: true,
		},
		{
			name:    "zero movie list ttl",
			mutate:  func(c *Config) { c.Cache.MovieListTTL = 0 },
			wantErr: true,
		},
		{
			name:    "zero shutdown timeout",
			mutate:  func(c *Config) { c.ShutdownTimeout = 0 },
			wantErr: true,
		},
		{
			name:    "negative shutdown timeout",
			mutate:  func(c *Config) { c.ShutdownTimeout = -1 * time.Second },
			wantErr: true,
		},
		{
			name:    "negative redis db",
			mutate:  func(c *Config) { c.Redis.DB = -1 },
			wantErr: true,
		},
		{
			name:    "redis db zero is valid",
			mutate:  func(c *Config) { c.Redis.DB = 0 },
			wantErr: false,
		},
		{
			name:    "redis db positive is valid",
			mutate:  func(c *Config) { c.Redis.DB = 15 },
			wantErr: false,
		},
		{
			name: "syncer enabled without api_key",
			mutate: func(c *Config) {
				c.Syncer = SyncerConfig{
					Enabled:            true,
					APIKey:             "",
					BaseURL:            "https://example.com",
					DailyRequestBudget: 100,
				}
			},
			wantErr: true,
		},
		{
			name: "syncer enabled without base_url",
			mutate: func(c *Config) {
				c.Syncer = SyncerConfig{
					Enabled:            true,
					APIKey:             "secret",
					BaseURL:            "",
					DailyRequestBudget: 100,
				}
			},
			wantErr: true,
		},
		{
			name: "syncer enabled with zero daily_request_budget",
			mutate: func(c *Config) {
				c.Syncer = SyncerConfig{
					Enabled:            true,
					APIKey:             "secret",
					BaseURL:            "https://example.com",
					DailyRequestBudget: 0,
				}
			},
			wantErr: true,
		},
		{
			name: "syncer enabled with negative daily_request_budget",
			mutate: func(c *Config) {
				c.Syncer = SyncerConfig{
					Enabled:            true,
					APIKey:             "secret",
					BaseURL:            "https://example.com",
					DailyRequestBudget: -1,
				}
			},
			wantErr: true,
		},
		{
			name: "syncer enabled with all fields set is valid",
			mutate: func(c *Config) {
				c.Syncer = SyncerConfig{
					Enabled:            true,
					APIKey:             "secret",
					BaseURL:            "https://example.com",
					DailyRequestBudget: 500,
				}
			},
			wantErr: false,
		},
		{
			name: "syncer disabled without api_key is valid",
			mutate: func(c *Config) {
				c.Syncer = SyncerConfig{
					Enabled:            false,
					APIKey:             "",
					DailyRequestBudget: 0,
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfigDefaultIsInvalidWithoutRequiredFields(t *testing.T) {
	t.Parallel()

	// Default() doesn't set postgres URL, so it should fail validation
	cfg := Default()
	if err := cfg.Validate(); err == nil {
		t.Fatal("Default() config should fail validation without postgres URL")
	}
}

func TestConfigDefaultHasSensibleValues(t *testing.T) {
	t.Parallel()

	cfg := Default()

	if cfg.GRPC.Addr == "" {
		t.Error("Default GRPC addr should not be empty")
	}
	if cfg.Cache.MovieTTL <= 0 {
		t.Error("Default MovieTTL should be positive")
	}
	if cfg.Cache.MovieListTTL <= 0 {
		t.Error("Default MovieListTTL should be positive")
	}
	if cfg.ShutdownTimeout <= 0 {
		t.Error("Default ShutdownTimeout should be positive")
	}
	if cfg.Syncer.BaseURL == "" {
		t.Error("Default Syncer.BaseURL should not be empty")
	}
	if cfg.Syncer.DailyRequestBudget <= 0 {
		t.Error("Default Syncer.DailyRequestBudget should be positive")
	}
}

func TestConfigStringContainsKeyFields(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	s := cfg.String()

	if s == "" {
		t.Fatal("String() should not return empty string")
	}
	// Should contain the grpc address
	if len(s) < 4 {
		t.Errorf("String() too short: %q", s)
	}
}
