package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTokensEqual(t *testing.T) {
	if tokensEqual("", "anything") {
		t.Fatal("empty expected token must not match")
	}
	if !tokensEqual("secret", "secret") {
		t.Fatal("matching tokens should succeed")
	}
	if tokensEqual("secret", "Secret") {
		t.Fatal("token compare must be exact")
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	if !isLoopbackAddr("127.0.0.1:8080") {
		t.Fatal("127.0.0.1 should be loopback")
	}
	if !isLoopbackAddr("localhost:8080") {
		t.Fatal("localhost should be loopback")
	}
	if isLoopbackAddr(":8080") {
		t.Fatal(":8080 binds all interfaces")
	}
	if isLoopbackAddr("0.0.0.0:8080") {
		t.Fatal("0.0.0.0 is not loopback")
	}
}

func TestValidateListenSecurity(t *testing.T) {
	if err := validateListenSecurity("127.0.0.1:8080", "", "", "", false, false); err == nil {
		t.Fatal("missing token on loopback must fail without allow-insecure-no-auth")
	}
	if err := validateListenSecurity("127.0.0.1:8080", "", "", "tok", false, false); err != nil {
		t.Fatalf("loopback + token + HTTP should be allowed: %v", err)
	}
	if err := validateListenSecurity(":8080", "", "", "tok", false, false); err == nil {
		t.Fatal("plain HTTP on all interfaces must fail without TLS or allow-insecure-http")
	}
	if err := validateListenSecurity(":8080", "", "", "tok", true, false); err != nil {
		t.Fatalf("allow-insecure-http should permit plain HTTP: %v", err)
	}
	if err := validateListenSecurity(":8080", "cert.pem", "", "tok", false, false); err == nil {
		t.Fatal("cert without key must fail")
	}
}

func TestAuthRejectsUnauthenticatedAPI(t *testing.T) {
	store := &Store{rules: map[string]Rule{
		"ssh": {ID: "ssh", Protocol: "tcp", DstPort: 22, Action: "allow"},
	}, filePath: filepath.Join(t.TempDir(), "rules.json")}
	handler := newMux(store, "test-token", false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET /api/v1/rules: got %d want 401", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/rules", strings.NewReader(`{"id":"x","protocol":"tcp","dst_port":1,"action":"drop"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST /api/v1/rules: got %d want 401", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health should stay public: got %d", rec.Code)
	}
}

func TestAuthAllowsBearerAndHeader(t *testing.T) {
	store := &Store{rules: map[string]Rule{
		"ssh": {ID: "ssh", Protocol: "tcp", DstPort: 22, Action: "allow"},
	}, filePath: filepath.Join(t.TempDir(), "rules.json")}
	handler := newMux(store, "test-token", false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Bearer token: got %d want 200 body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	req.Header.Set("X-API-Token", "test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("X-API-Token: got %d want 200", rec.Code)
	}
}

func TestWritePrivateFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := writePrivateFile(path, []byte(`{"rules":[]}`)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != rulesFilePerm {
		t.Fatalf("rules file mode = %o, want %o", info.Mode().Perm(), rulesFilePerm)
	}
	var parsed map[string]json.RawMessage
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
}
