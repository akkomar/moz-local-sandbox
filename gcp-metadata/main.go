// ccode-gcp-metadata is a host-side HTTP server that emulates the subset of
// the GCE metadata API needed for GCP client libraries to authenticate as
// an impersonated service account. The launcher starts it OUTSIDE the
// sandbox; the sandboxed process reaches it via GCE_METADATA_HOST pointing
// at the loopback port.
//
// Source identity is the host user's ADC (whatever `gcloud auth` is set to).
// On each token refresh, the server shells out to:
//
//	gcloud auth print-access-token \
//	    --impersonate-service-account=<sa> \
//	    --lifetime=<ttl>
//
// which uses the user's ADC to call iamcredentials.generateAccessToken on
// the host. The minted token is cached in-process and refreshed ~5min
// before expiry.
//
// Only GET endpoints needed by gcloud / bq / google-auth (Python) /
// oauth2/google (Go) are implemented. ID-token issuance is intentionally
// not supported.
//
// Output (stdout, single line, key=value):
//
//	PORT=<port> SA=<email> PROJECT=<id>
//
// Stderr gets human-readable startup + per-request log lines.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(os.Stderr)

	var (
		saEmail  = flag.String("sa", "", "service account email to impersonate (required)")
		project  = flag.String("project", "", "project id served from /project/project-id (required)")
		bindHost = flag.String("bind", "127.0.0.1", "loopback interface to bind on")
		ttl      = flag.Duration("ttl", time.Hour, "requested token lifetime")
		safety   = flag.Duration("refresh-safety", 5*time.Minute, "refresh tokens this long before expiry")
	)
	flag.Parse()

	if *saEmail == "" {
		fatal("--sa is required")
	}
	if *project == "" {
		fatal("--project is required")
	}
	if !strings.Contains(*saEmail, "@") {
		fatal("--sa does not look like an email: %q", *saEmail)
	}

	cache := &tokenCache{
		sa:      *saEmail,
		ttl:     *ttl,
		safety:  *safety,
		refresh: gcloudPrintAccessToken,
	}

	srv := &server{
		saEmail: *saEmail,
		project: *project,
		cache:   cache,
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(*bindHost, "0"))
	if err != nil {
		fatal("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	httpSrv := &http.Server{
		Handler:      srv,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Machine-readable status line on stdout for the launcher to parse.
	// Sync so the parent (waiting on read) sees it before we block on Serve.
	fmt.Printf("PORT=%d SA=%s PROJECT=%s\n", port, *saEmail, *project)
	_ = os.Stdout.Sync()
	log.Printf("gcp-metadata on %s (sa=%s project=%s)", ln.Addr(), *saEmail, *project)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		s := <-sig
		log.Printf("shutdown: signal %s", s)
		shutdownCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = httpSrv.Shutdown(shutdownCtx)
		cancel()
	}()

	if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Printf("serve: %v", err)
	}
	<-ctx.Done()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ccode-gcp-metadata: "+strings.TrimRight(format, "\n")+"\n", args...)
	os.Exit(1)
}
