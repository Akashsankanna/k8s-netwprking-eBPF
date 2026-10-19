// phase4_api_server.go
// REST API for the firewall: full CRUD over rules (persisted to a JSON
// file and mirrored into the pinned eBPF rules map), plus live stats and
// a health check. This is the only phase meant to be internet/LAN-facing,
// so put it behind auth/TLS in production — see QUICKSTART.md.
//
// Build: go build -o phase4-api-server phase4_api_server.go
// Run:   ./phase4-api-server -listen :8080 -seed
//
// Endpoints:
//   GET    /health
//   GET    /api/v1/stats
//   GET    /api/v1/rules
//   POST   /api/v1/rules
//   PUT    /api/v1/rules/{id}
//   DELETE /api/v1/rules/{id}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

const (
	pinnedRulesMapPath = "/sys/fs/bpf/firewall_rules"
	pinnedStatsMapPath = "/sys/fs/bpf/firewall_stats"
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
	return os.WriteFile(s.filePath, data, 0644)
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
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
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
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func main() {
	listen := flag.String("listen", ":8080", "address to listen on")
	rulesFile := flag.String("rules-file", "example_rules.json", "JSON file used to persist rules")
	seed := flag.Bool("seed", false, "load rules-file into the store on startup")
	flag.Parse()

	store := NewStore(*rulesFile)
	if *seed {
		if err := store.LoadFromFile(); err != nil {
			log.Fatalf("seeding rules from %s: %v", *rulesFile, err)
		}
		log.Printf("seeded %d rules from %s", len(store.rules), *rulesFile)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", store.handleHealth)
	mux.HandleFunc("/api/v1/stats", store.handleStats)
	mux.HandleFunc("/api/v1/rules", store.handleRulesCollection)
	mux.HandleFunc("/api/v1/rules/", store.handleRuleItem)

	log.Printf("✅ Phase 4 API server listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
