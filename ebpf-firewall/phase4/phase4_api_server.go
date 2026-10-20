// phase4_api_server.go
// REST API for the firewall: full CRUD over rules (persisted to a JSON
// file and mirrored into the pinned eBPF rules map), plus live stats and
// a health check.
//
// Security defaults:
//   - API token required for /api/v1/* (Authorization: Bearer or X-API-Token)
//   - Bind to loopback unless you pass a wider -listen address
//   - TLS when -tls-cert and -tls-key are set; plain HTTP allowed on loopback
//   - Rules file written with 0600 permissions
//
// Build: go build -o phase4-api-server phase4_api_server.go
// Run:   FIREWALL_API_TOKEN=... ./phase4-api-server -listen 127.0.0.1:8080 -seed
//
// Endpoints:
//   GET    /health                 (unauthenticated liveness)
//   GET    /api/v1/stats           (authenticated)
//   GET    /api/v1/rules
//   POST   /api/v1/rules
//   PUT    /api/v1/rules/{id}
//   DELETE /api/v1/rules/{id}

package main

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

const (
	pinnedRulesMapPath = "/sys/fs/bpf/firewall_rules"
	pinnedStatsMapPath = "/sys/fs/bpf/firewall_stats"
	maxBodyBytes       = 1 << 20
	rulesFilePerm      = 0o600
)

const (
	actionAllow uint8 = 0
	actionDrop  uint8 = 1
)

var protoNumbers = map[string]uint8{"icmp": 1, "tcp": 6, "udp": 17, "any": 0}
var protoNames = map[uint8]string{1: "icmp", 6: "tcp", 17: "udp", 0: "any"}

// Must byte-for-byte match struct rule_key in phase1_packet_filter.c
// (unpacked: size=4, dst_port at offset 2). See phase3's comment for detail.
type ruleKey struct {
	Protocol uint8
	_        uint8
	DstPort  uint16
}

type ruleValue struct {
	Action     uint8
	_          [7]byte
	MatchCount uint64
}

// Rule is the API-facing representation (includes id/description that the
// raw eBPF map doesn't store).
type Rule struct {
	ID          string `json:"id"`
	Protocol    string `json:"protocol"`
	DstPort     uint16 `json:"dst_port"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
}

type Store struct {
	mu       sync.RWMutex
	rules    map[string]Rule // id -> rule
	rulesMap *ebpf.Map       // nil if phase1 isn't running / map not found
	statsMap *ebpf.Map
	filePath string
}

func NewStore(filePath string) *Store {
	s := &Store{rules: make(map[string]Rule), filePath: filePath}

	if m, err := ebpf.LoadPinnedMap(pinnedRulesMapPath, nil); err == nil {
		s.rulesMap = m
	} else {
		log.Printf("  rules map not available (%v) — API will run in file-only mode until phase1 is up", err)
	}
	if m, err := ebpf.LoadPinnedMap(pinnedStatsMapPath, nil); err == nil {
		s.statsMap = m
	} else {
		log.Printf(" stats map not available (%v) — /api/v1/stats will return zeros", err)
	}
	return s
}

func (s *Store) LoadFromFile() error {
	data, err := os.ReadFile(s.filePath)
	if os.IsNotExist(err) {
		return nil // fine, start empty
	}
	if err != nil {
		return err
	}
	if err := tightenFilePerms(s.filePath); err != nil {
		log.Printf("could not restrict permissions on %s: %v", s.filePath, err)
	}
	var rf struct {
		Rules []Rule `json:"rules"`
	}
	if err := json.Unmarshal(data, &rf); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range rf.Rules {
		s.rules[r.ID] = r
	}
	return nil
}

func (s *Store) persistLocked() error {
	list := make([]Rule, 0, len(s.rules))
	for _, r := range s.rules {
		list = append(list, r)
	}
	data, err := json.MarshalIndent(struct {
		Rules []Rule `json:"rules"`
	}{list}, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(s.filePath, data)
}

func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".rules-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(rulesFilePerm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return tightenFilePerms(path)
}

func tightenFilePerms(path string) error {
	return os.Chmod(path, rulesFilePerm)
}

func validateRule(r Rule) error {
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}
	if _, ok := protoNumbers[r.Protocol]; !ok {
		return fmt.Errorf("protocol must be one of tcp/udp/icmp/any")
	}
	if r.Action != "allow" && r.Action != "drop" {
		return fmt.Errorf("action must be 'allow' or 'drop'")
	}
	return nil
}

func (s *Store) syncToMapLocked(r Rule, delete bool) error {
	if s.rulesMap == nil {
		return nil // file-only mode
	}
	k := ruleKey{Protocol: protoNumbers[r.Protocol], DstPort: r.DstPort}
	if delete {
		return s.rulesMap.Delete(&k)
	}
	action := actionAllow
	if r.Action == "drop" {
		action = actionDrop
	}
	v := ruleValue{Action: action}
	return s.rulesMap.Put(&k, &v)
}

// ---- HTTP handlers ----

func (s *Store) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"time":         time.Now().UTC().Format(time.RFC3339),
		"rules_map_up": s.rulesMap != nil,
		"stats_map_up": s.statsMap != nil,
	})
}

func (s *Store) handleStats(w http.ResponseWriter, r *http.Request) {
	labels := []string{"total", "dropped", "allowed", "icmp_dropped"}
	out := map[string]uint64{}
	if s.statsMap != nil {
		for i, name := range labels {
			var val uint64
			idx := uint32(i)
			if err := s.statsMap.Lookup(&idx, &val); err == nil {
				out[name] = val
			}
		}
	} else {
		for _, name := range labels {
			out[name] = 0
		}
	}
	s.mu.RLock()
	ruleCount := len(s.rules)
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"packets": out, "rule_count": ruleCount})
}

func (s *Store) handleRulesCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		list := make([]Rule, 0, len(s.rules))
		for _, rule := range s.rules {
			list = append(list, rule)
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"rules": list})

	case http.MethodPost:
		var rule Rule
		if err := decodeJSONBody(r, &rule); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if err := validateRule(rule); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.mu.Lock()
		if _, exists := s.rules[rule.ID]; exists {
			s.mu.Unlock()
			writeError(w, http.StatusConflict, fmt.Sprintf("rule %q already exists", rule.ID))
			return
		}
		s.rules[rule.ID] = rule
		err := s.syncToMapLocked(rule, false)
		perr := s.persistLocked()
		s.mu.Unlock()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "rule saved to file but eBPF map update failed: "+err.Error())
			return
		}
		if perr != nil {
			writeError(w, http.StatusInternalServerError, "rule applied but failed to persist to disk: "+perr.Error())
			return
		}
		writeJSON(w, http.StatusCreated, rule)

	default:
		writeError(w, http.StatusMethodNotAllowed, "use GET or POST on /api/v1/rules")
	}
}

func (s *Store) handleRuleItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/rules/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing rule id")
		return
	}

	switch r.Method {
	case http.MethodPut:
		var rule Rule
		if err := decodeJSONBody(r, &rule); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		rule.ID = id
		if err := validateRule(rule); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.mu.Lock()
		old, existed := s.rules[id]
		s.rules[id] = rule
		if existed && (old.Protocol != rule.Protocol || old.DstPort != rule.DstPort) {
			_ = s.syncToMapLocked(old, true) // remove stale map key if proto/port changed
		}
		err := s.syncToMapLocked(rule, false)
		perr := s.persistLocked()
		s.mu.Unlock()
		if err != nil || perr != nil {
			writeError(w, http.StatusInternalServerError, "update partially failed")
			return
		}
		writeJSON(w, http.StatusOK, rule)

	case http.MethodDelete:
		s.mu.Lock()
		rule, existed := s.rules[id]
		if !existed {
			s.mu.Unlock()
			writeError(w, http.StatusNotFound, fmt.Sprintf("rule %q not found", id))
			return
		}
		delete(s.rules, id)
		err := s.syncToMapLocked(rule, true)
		perr := s.persistLocked()
		s.mu.Unlock()
		if err != nil || perr != nil {
			writeError(w, http.StatusInternalServerError, "delete partially failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		writeError(w, http.StatusMethodNotAllowed, "use PUT or DELETE on /api/v1/rules/{id}")
	}
}

func decodeJSONBody(r *http.Request, v any) error {
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, maxBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > maxBodyBytes {
		return fmt.Errorf("request body too large")
	}
	return json.Unmarshal(data, v)
}

func requestToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) >= 7 && strings.EqualFold(auth[:7], "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return strings.TrimSpace(r.Header.Get("X-API-Token"))
}

func tokensEqual(expected, got string) bool {
	if expected == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1 {
		return true
	}
	return false
}

func withAuth(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokensEqual(token, requestToken(r)) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ebpf-firewall"`)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false // ":8080" listens on all interfaces
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateListenSecurity(addr, cert, key, token string, allowHTTP, allowNoAuth bool) error {
	if token == "" && !allowNoAuth {
		return fmt.Errorf("API token required: set -api-token or FIREWALL_API_TOKEN (or pass -allow-insecure-no-auth for a closed lab only)")
	}
	https := cert != "" || key != ""
	if https && (cert == "" || key == "") {
		return fmt.Errorf("both -tls-cert and -tls-key are required for HTTPS")
	}
	if !https && !isLoopbackAddr(addr) && !allowHTTP {
		return fmt.Errorf("plain HTTP is only allowed on loopback; set -tls-cert/-tls-key, bind 127.0.0.1, or pass -allow-insecure-http behind a TLS proxy")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func newMux(store *Store, token string, allowNoAuth bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", store.handleHealth)
	protect := func(h http.HandlerFunc) http.HandlerFunc {
		if allowNoAuth && token == "" {
			return h
		}
		return withAuth(token, h)
	}
	mux.HandleFunc("/api/v1/stats", protect(store.handleStats))
	mux.HandleFunc("/api/v1/rules", protect(store.handleRulesCollection))
	mux.HandleFunc("/api/v1/rules/", protect(store.handleRuleItem))
	return mux
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "address to listen on (default loopback)")
	rulesFile := flag.String("rules-file", "example_rules.json", "JSON file used to persist rules")
	seed := flag.Bool("seed", false, "load rules-file into the store on startup")
	apiToken := flag.String("api-token", os.Getenv("FIREWALL_API_TOKEN"), "API bearer token (or FIREWALL_API_TOKEN)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate PEM (enables HTTPS)")
	tlsKey := flag.String("tls-key", "", "TLS private key PEM")
	allowHTTP := flag.Bool("allow-insecure-http", false, "allow plain HTTP on a non-loopback address (use only behind a trusted TLS reverse proxy)")
	allowNoAuth := flag.Bool("allow-insecure-no-auth", false, "allow unauthenticated API access (closed lab only)")
	flag.Parse()

	if err := validateListenSecurity(*listen, *tlsCert, *tlsKey, *apiToken, *allowHTTP, *allowNoAuth); err != nil {
		log.Fatal(err)
	}

	store := NewStore(*rulesFile)
	if *seed {
		if err := store.LoadFromFile(); err != nil {
			log.Fatalf("seeding rules from %s: %v", *rulesFile, err)
		}
		log.Printf("seeded %d rules from %s", len(store.rules), *rulesFile)
	}

	handler := newMux(store, *apiToken, *allowNoAuth)
	srv := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	if *apiToken != "" {
		log.Printf("authentication enabled for /api/v1/*")
	} else {
		log.Printf("WARNING: API authentication disabled (-allow-insecure-no-auth)")
	}
	if *tlsCert != "" {
		log.Printf("Phase 4 API server listening on https://%s", *listen)
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	}
	if !isLoopbackAddr(*listen) {
		log.Printf("WARNING: plain HTTP on non-loopback %s; TLS must be terminated by a trusted reverse proxy", *listen)
	}
	log.Printf("Phase 4 API server listening on http://%s", *listen)
	log.Fatal(srv.ListenAndServe())
}
