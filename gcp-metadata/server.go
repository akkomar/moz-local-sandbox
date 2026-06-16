package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

const metadataFlavor = "Google"

// server implements the GCE metadata API subset needed by gcloud, bq,
// google-auth (Python), and oauth2/google (Go). Endpoints not listed in
// the switch return 404 with a plain-text body.
type server struct {
	saEmail string
	project string
	cache   *tokenCache
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// All responses set Metadata-Flavor: Google so clients identify us as
	// a real metadata server.
	w.Header().Set("Metadata-Flavor", metadataFlavor)
	w.Header().Set("Server", "Metadata Server for VM")

	// The real metadata server requires this header on every request to
	// defend against SSRF. Mirror that behaviour.
	if r.Header.Get("Metadata-Flavor") != metadataFlavor {
		http.Error(w, "missing Metadata-Flavor: Google header", http.StatusForbidden)
		log.Printf("DENY %s %s (no Metadata-Flavor header)", r.Method, r.URL.Path)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path
	saPrefix := "/computeMetadata/v1/instance/service-accounts/"
	defaultPrefix := saPrefix + "default"
	emailPrefix := saPrefix + s.saEmail

	switch {
	case path == "/":
		// Probe endpoint. The real server returns "0.1/\ncomputeMetadata/\n".
		writeText(w, "0.1/\ncomputeMetadata/\n")

	case path == "/computeMetadata/" || path == "/computeMetadata":
		writeText(w, "v1/\n")

	case path == "/computeMetadata/v1/" || path == "/computeMetadata/v1":
		writeText(w, "instance/\nproject/\n")

	case path == "/computeMetadata/v1/instance/" || path == "/computeMetadata/v1/instance":
		writeText(w, "service-accounts/\n")

	case path == saPrefix || path == strings.TrimSuffix(saPrefix, "/"):
		writeText(w, "default/\n"+s.saEmail+"/\n")

	case path == defaultPrefix+"/" || path == defaultPrefix,
		path == emailPrefix+"/" || path == emailPrefix:
		// google-auth's get_service_account_info() calls this endpoint
		// with `?recursive=true` and expects a JSON object back; gcloud
		// crashes with `TypeError: string indices must be integers`
		// when it gets a plain-text directory listing instead. Detect
		// the query param and switch shape.
		if r.URL.Query().Get("recursive") == "true" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"email":   s.saEmail,
				"scopes":  []string{"https://www.googleapis.com/auth/cloud-platform"},
				"aliases": []string{"default"},
			})
		} else {
			writeText(w, "aliases\nemail\nscopes\ntoken\n")
		}

	case path == defaultPrefix+"/email", path == emailPrefix+"/email":
		writeText(w, s.saEmail)

	case path == defaultPrefix+"/aliases", path == emailPrefix+"/aliases":
		writeText(w, "default")

	case path == defaultPrefix+"/scopes", path == emailPrefix+"/scopes":
		writeText(w, "https://www.googleapis.com/auth/cloud-platform")

	case path == defaultPrefix+"/token", path == emailPrefix+"/token":
		s.handleToken(w, r)

	case path == defaultPrefix+"/identity", path == emailPrefix+"/identity":
		// ID-token issuance is intentionally not supported. gcloud
		// treats 501 here as fatal (it surfaces as
		// "MetadataServerException: HTTP Error 501" and aborts
		// otherwise-unrelated calls like `auth print-access-token`).
		// 404 is the right shape: callers see "this metadata server
		// doesn't issue identity tokens" and fall through to whatever
		// fallback they have for ID tokens, while access-token flows
		// continue to work.
		http.NotFound(w, r)
		log.Printf("MISS %s %s (identity endpoint not implemented)", r.Method, r.URL.Path)
		return

	case path == "/computeMetadata/v1/universe/universe-domain":
		// "Universe domain" identifies whether this VM is in the public
		// Google Cloud universe ("googleapis.com") or a sovereign /
		// sandbox universe. Newer gcloud and google-auth versions
		// probe this on startup to choose the right API host suffix.
		// 404 makes them default to "googleapis.com" which is what we
		// want, but explicitly returning it is one fewer retry / log
		// noise per command.
		writeText(w, "googleapis.com")

	case path == "/computeMetadata/v1/project/" || path == "/computeMetadata/v1/project":
		writeText(w, "numeric-project-id\nproject-id\n")

	case path == "/computeMetadata/v1/project/project-id":
		writeText(w, s.project)

	case path == "/computeMetadata/v1/project/numeric-project-id":
		// gcloud probes this endpoint to detect "am I on GCE?" -- the
		// check is `.isdigit()` on the response body. Returning a digit
		// string here is what flips gcloud into GCE-mode auth (falling
		// through to the metadata server for tokens instead of looking
		// up the active account in credentials.db). The value itself
		// isn't a real numeric project ID; emit a placeholder.
		writeText(w, "0")

	default:
		http.Error(w, "not found", http.StatusNotFound)
		log.Printf("MISS %s %s", r.Method, r.URL.Path)
		return
	}

	log.Printf("ALLOW %s %s", r.Method, r.URL.Path)
}

func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	tok, err := s.cache.Get(ctx)
	if err != nil {
		log.Printf("token refresh failed: %v", err)
		http.Error(w, "token refresh failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	expiresIn := int(time.Until(tok.ExpiresAt).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	resp := struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}{
		AccessToken: tok.AccessToken,
		ExpiresIn:   expiresIn,
		TokenType:   "Bearer",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeText(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/text")
	_, _ = w.Write([]byte(body))
}
