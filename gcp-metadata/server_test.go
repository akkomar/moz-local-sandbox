package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testSA      = "bqetl-dev-sandbox@data-proto.iam.gserviceaccount.com"
	testProject = "data-proto"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := &server{
		saEmail: testSA,
		project: testProject,
		cache: &tokenCache{
			sa:     testSA,
			ttl:    time.Hour,
			safety: 5 * time.Minute,
			refresh: func(ctx context.Context, sa string, ttl time.Duration) (Token, error) {
				return Token{AccessToken: "ya29.test-token", ExpiresAt: time.Now().Add(ttl)}, nil
			},
		},
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts
}

// do GETs a path with the Metadata-Flavor header set, returning status,
// body, and the response's Metadata-Flavor header.
func do(t *testing.T, ts *httptest.Server, path string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Do %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header.Get("Metadata-Flavor")
}

func TestServer_RequiresMetadataFlavorHeader(t *testing.T) {
	ts := newTestServer(t)
	resp, err := ts.Client().Get(ts.URL + "/computeMetadata/v1/instance/service-accounts/default/token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("without Metadata-Flavor header: status = %d, want 403", resp.StatusCode)
	}
}

func TestServer_RootProbe(t *testing.T) {
	ts := newTestServer(t)
	status, body, flavor := do(t, ts, "/")
	if status != http.StatusOK {
		t.Errorf("GET /: status = %d, want 200", status)
	}
	if flavor != "Google" {
		t.Errorf("GET /: Metadata-Flavor = %q, want Google", flavor)
	}
	if !strings.Contains(body, "computeMetadata/") {
		t.Errorf("GET /: body = %q, want to contain computeMetadata/", body)
	}
}

func TestServer_TokenEndpoint_Default(t *testing.T) {
	ts := newTestServer(t)
	status, body, _ := do(t, ts, "/computeMetadata/v1/instance/service-accounts/default/token")
	if status != http.StatusOK {
		t.Errorf("token: status = %d, want 200", status)
	}
	var got struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode token JSON: %v (body=%q)", err, body)
	}
	if got.AccessToken != "ya29.test-token" {
		t.Errorf("access_token = %q, want ya29.test-token", got.AccessToken)
	}
	if got.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", got.TokenType)
	}
	if got.ExpiresIn < 3000 || got.ExpiresIn > 3600 {
		t.Errorf("expires_in = %d, want 3000-3600 (1h minus a few seconds)", got.ExpiresIn)
	}
}

func TestServer_TokenEndpoint_ByEmail(t *testing.T) {
	ts := newTestServer(t)
	status, body, _ := do(t, ts, "/computeMetadata/v1/instance/service-accounts/"+testSA+"/token")
	if status != http.StatusOK {
		t.Errorf("token-by-email: status = %d, want 200 (body=%q)", status, body)
	}
}

func TestServer_EmailEndpoint(t *testing.T) {
	ts := newTestServer(t)
	status, body, _ := do(t, ts, "/computeMetadata/v1/instance/service-accounts/default/email")
	if status != http.StatusOK {
		t.Errorf("email: status = %d, want 200", status)
	}
	if body != testSA {
		t.Errorf("email body = %q, want %q", body, testSA)
	}
}

func TestServer_ProjectId(t *testing.T) {
	ts := newTestServer(t)
	status, body, _ := do(t, ts, "/computeMetadata/v1/project/project-id")
	if status != http.StatusOK {
		t.Errorf("project-id: status = %d, want 200", status)
	}
	if body != testProject {
		t.Errorf("project-id body = %q, want %q", body, testProject)
	}
}

func TestServer_Scopes(t *testing.T) {
	ts := newTestServer(t)
	status, body, _ := do(t, ts, "/computeMetadata/v1/instance/service-accounts/default/scopes")
	if status != http.StatusOK {
		t.Errorf("scopes: status = %d, want 200", status)
	}
	if !strings.Contains(body, "cloud-platform") {
		t.Errorf("scopes body = %q, want to contain cloud-platform", body)
	}
}

func TestServer_DirectoryListings(t *testing.T) {
	ts := newTestServer(t)
	cases := []struct {
		path string
		want string
	}{
		{"/computeMetadata/v1/instance/service-accounts/", "default/"},
		{"/computeMetadata/v1/instance/service-accounts/", testSA + "/"},
		{"/computeMetadata/v1/instance/service-accounts/default/", "token"},
		{"/computeMetadata/v1/project/", "project-id"},
	}
	for _, tc := range cases {
		status, body, _ := do(t, ts, tc.path)
		if status != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", tc.path, status)
		}
		if !strings.Contains(body, tc.want) {
			t.Errorf("GET %s: body = %q, want to contain %q", tc.path, body, tc.want)
		}
	}
}

func TestServer_IdentityEndpoint_404(t *testing.T) {
	// Must be 404, NOT 501: gcloud surfaces 501 as a fatal
	// MetadataServerException that breaks `gcloud auth print-access-token`.
	// 404 cleanly signals "no identity-token issuance here" without
	// poisoning the access-token flow.
	ts := newTestServer(t)
	status, _, _ := do(t, ts, "/computeMetadata/v1/instance/service-accounts/default/identity?audience=foo")
	if status != http.StatusNotFound {
		t.Errorf("identity: status = %d, want 404", status)
	}
}

func TestServer_RecursiveServiceAccountReturnsJSON(t *testing.T) {
	// google-auth's get_service_account_info() hits
	// `service-accounts/<email>/?recursive=true` and parses the body
	// as JSON. Without this branch, gcloud crashes with TypeError.
	ts := newTestServer(t)
	cases := []string{
		"/computeMetadata/v1/instance/service-accounts/default/?recursive=true",
		"/computeMetadata/v1/instance/service-accounts/" + testSA + "/?recursive=true",
	}
	for _, p := range cases {
		status, body, _ := do(t, ts, p)
		if status != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", p, status)
			continue
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Errorf("GET %s: body is not JSON: %v (body=%q)", p, err, body)
			continue
		}
		if got["email"] != testSA {
			t.Errorf("GET %s: email = %v, want %s", p, got["email"], testSA)
		}
		if _, ok := got["scopes"]; !ok {
			t.Errorf("GET %s: missing scopes key", p)
		}
	}
}

func TestServer_UniverseDomain(t *testing.T) {
	ts := newTestServer(t)
	status, body, _ := do(t, ts, "/computeMetadata/v1/universe/universe-domain")
	if status != http.StatusOK {
		t.Errorf("universe-domain: status = %d, want 200", status)
	}
	if body != "googleapis.com" {
		t.Errorf("universe-domain: body = %q, want googleapis.com", body)
	}
}

func TestServer_UnknownPath404(t *testing.T) {
	ts := newTestServer(t)
	status, _, _ := do(t, ts, "/computeMetadata/v1/some/random/path")
	if status != http.StatusNotFound {
		t.Errorf("unknown path: status = %d, want 404", status)
	}
}

func TestServer_NumericProjectIdReturnsDigit(t *testing.T) {
	// gcloud's GCE-detection probe calls .isdigit() on this response.
	// A non-empty digit string is what makes gcloud treat the env as
	// "I'm running on GCE" and use the metadata server for auth.
	ts := newTestServer(t)
	status, body, _ := do(t, ts, "/computeMetadata/v1/project/numeric-project-id")
	if status != http.StatusOK {
		t.Errorf("numeric-project-id: status = %d, want 200", status)
	}
	if body == "" {
		t.Error("numeric-project-id: empty body would defeat GCE detection")
	}
	for _, r := range body {
		if r < '0' || r > '9' {
			t.Errorf("numeric-project-id: body %q must be all digits (gcloud .isdigit() check)", body)
			break
		}
	}
}

func TestServer_NonGETRejected(t *testing.T) {
	ts := newTestServer(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Do POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST token: status = %d, want 405", resp.StatusCode)
	}
}
