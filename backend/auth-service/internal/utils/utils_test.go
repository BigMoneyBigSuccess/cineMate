package utils

import (
	"os"
	"testing"

	"github.com/google/uuid"
)

func TestMain(m *testing.M) {
	os.Setenv("JWT_SECRET", "test-secret-key-at-least-32-chars!!")
	if err := LoadJWTSecret(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func TestGenerateAndParseJWT_Roundtrip(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	token, err := GenerateJWT(id.String())
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	parsed, err := ParseJWT(token)
	if err != nil {
		t.Fatalf("ParseJWT: %v", err)
	}

	if parsed != id {
		t.Fatalf("got %s, want %s", parsed, id)
	}
}

func TestGenerateJWT_RejectsInvalidUUID(t *testing.T) {
	t.Parallel()

	_, err := GenerateJWT("not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid UUID, got nil")
	}
}

func TestParseJWT_RejectsGarbage(t *testing.T) {
	t.Parallel()

	tokens := []string{"", "garbage", "a.b.c", "Bearer token"}
	for _, tok := range tokens {
		if _, err := ParseJWT(tok); err == nil {
			t.Errorf("ParseJWT(%q): expected error, got nil", tok)
		}
	}
}

func TestHashPassword_ProducesDistinctHashes(t *testing.T) {
	t.Parallel()

	h1, err := HashPassword("password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	h2, err := HashPassword("password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if h1 == h2 {
		t.Fatal("same input produced identical hashes (no salt?)")
	}
}

func TestCheckPassword(t *testing.T) {
	t.Parallel()

	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if !CheckPassword(hash, "correct-horse-battery-staple") {
		t.Fatal("CheckPassword returned false for correct password")
	}
	if CheckPassword(hash, "wrong") {
		t.Fatal("CheckPassword returned true for wrong password")
	}
}
