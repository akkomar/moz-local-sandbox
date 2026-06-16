package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTokenCache_RefreshesOnFirstGet(t *testing.T) {
	calls := 0
	c := &tokenCache{
		sa:     "sa@p.iam.gserviceaccount.com",
		ttl:    time.Hour,
		safety: 5 * time.Minute,
		refresh: func(ctx context.Context, sa string, ttl time.Duration) (Token, error) {
			calls++
			return Token{AccessToken: "tok-1", ExpiresAt: time.Now().Add(ttl)}, nil
		},
	}

	tok, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if tok.AccessToken != "tok-1" {
		t.Errorf("AccessToken = %q, want tok-1", tok.AccessToken)
	}
	if calls != 1 {
		t.Errorf("refresh calls = %d, want 1", calls)
	}
}

func TestTokenCache_UsesCacheWhileFresh(t *testing.T) {
	calls := 0
	c := &tokenCache{
		sa:     "sa@p.iam.gserviceaccount.com",
		ttl:    time.Hour,
		safety: 5 * time.Minute,
		refresh: func(ctx context.Context, sa string, ttl time.Duration) (Token, error) {
			calls++
			return Token{AccessToken: "tok-fresh", ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}

	_, _ = c.Get(context.Background())
	_, _ = c.Get(context.Background())
	tok, _ := c.Get(context.Background())

	if calls != 1 {
		t.Errorf("refresh calls = %d, want 1 (cache should serve repeat reads)", calls)
	}
	if tok.AccessToken != "tok-fresh" {
		t.Errorf("AccessToken = %q, want tok-fresh", tok.AccessToken)
	}
}

func TestTokenCache_RefreshesWhenInsideSafetyMargin(t *testing.T) {
	calls := 0
	c := &tokenCache{
		sa:     "sa@p.iam.gserviceaccount.com",
		ttl:    time.Hour,
		safety: 5 * time.Minute,
	}
	c.refresh = func(ctx context.Context, sa string, ttl time.Duration) (Token, error) {
		calls++
		// First call: token expires in 1min (well inside the 5min safety
		// margin). Second call: token expires in 1h.
		if calls == 1 {
			return Token{AccessToken: "stale", ExpiresAt: time.Now().Add(time.Minute)}, nil
		}
		return Token{AccessToken: "fresh", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}

	tok1, _ := c.Get(context.Background())
	if tok1.AccessToken != "stale" {
		t.Errorf("first Get: AccessToken = %q, want stale", tok1.AccessToken)
	}

	tok2, _ := c.Get(context.Background())
	if tok2.AccessToken != "fresh" {
		t.Errorf("second Get: AccessToken = %q, want fresh (stale was inside safety margin)", tok2.AccessToken)
	}
	if calls != 2 {
		t.Errorf("refresh calls = %d, want 2", calls)
	}
}

func TestTokenCache_PropagatesRefreshError(t *testing.T) {
	wantErr := errors.New("gcloud blew up")
	c := &tokenCache{
		sa:     "sa@p.iam.gserviceaccount.com",
		ttl:    time.Hour,
		safety: 5 * time.Minute,
		refresh: func(ctx context.Context, sa string, ttl time.Duration) (Token, error) {
			return Token{}, wantErr
		},
	}

	_, err := c.Get(context.Background())
	if !errors.Is(err, wantErr) {
		t.Errorf("Get error = %v, want %v", err, wantErr)
	}
}
