package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Token is the cached impersonated SA access token plus its expiry.
type Token struct {
	AccessToken string
	ExpiresAt   time.Time
}

// refreshFunc mints a fresh token for the given SA with the requested
// lifetime. Split out so tests can inject a fake without calling gcloud.
type refreshFunc func(ctx context.Context, sa string, ttl time.Duration) (Token, error)

// tokenCache holds the current impersonated access token. Refresh is
// serialised under mu so concurrent requests don't trigger multiple
// simultaneous gcloud invocations.
type tokenCache struct {
	sa      string
	ttl     time.Duration
	safety  time.Duration
	refresh refreshFunc

	mu     sync.Mutex
	cached Token
}

// Get returns a token that has at least `safety` time left before expiry,
// minting a fresh one if needed.
func (c *tokenCache) Get(ctx context.Context) (Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cached.AccessToken != "" && time.Until(c.cached.ExpiresAt) > c.safety {
		return c.cached, nil
	}

	t, err := c.refresh(ctx, c.sa, c.ttl)
	if err != nil {
		return Token{}, err
	}
	c.cached = t
	log.Printf("token: refreshed, expires in %s", time.Until(t.ExpiresAt).Round(time.Second))
	return t, nil
}

// gcloudPrintAccessToken invokes `gcloud auth print-access-token` to mint an
// impersonated access token for the given SA. The lifetime requested is `ttl`
// seconds; gcloud writes the token to stdout. We can't read the actual expiry
// from gcloud's output, so we compute expiry as now + ttl. In practice the
// real expiry matches (the API honours --lifetime up to org-policy max);
// the cache's `safety` margin absorbs any small drift.
func gcloudPrintAccessToken(ctx context.Context, sa string, ttl time.Duration) (Token, error) {
	args := []string{
		"auth", "print-access-token",
		"--impersonate-service-account=" + sa,
		fmt.Sprintf("--lifetime=%d", int(ttl.Seconds())),
	}
	cmd := exec.CommandContext(ctx, "gcloud", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	if err := cmd.Run(); err != nil {
		return Token{}, fmt.Errorf("gcloud auth print-access-token: %w\nstderr: %s",
			err, strings.TrimSpace(stderr.String()))
	}
	tok := strings.TrimSpace(stdout.String())
	if tok == "" {
		return Token{}, fmt.Errorf("gcloud returned empty token; stderr: %s",
			strings.TrimSpace(stderr.String()))
	}
	return Token{
		AccessToken: tok,
		ExpiresAt:   start.Add(ttl),
	}, nil
}
