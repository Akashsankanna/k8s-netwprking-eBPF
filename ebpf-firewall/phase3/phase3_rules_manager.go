package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
)

const pinnedRulesMapPath = "/sys/fs/bpf/firewall_rules"

const (
	actionAllow uint8 = 0
	actionDrop  uint8 = 1
)

var protoNumbers = map[string]uint8{
	"icmp": 1,
	"tcp":  6,
	"udp":  17,
	"any":  0,
}

// Rule mirrors example_rules.json.
type Rule struct {
	ID          string `json:"id"`
	Protocol    string `json:"protocol"`
	DstPort     uint16 `json:"dst_port"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

type RuleFile struct {
	Rules []Rule `json:"rules"`
}

type ruleKey struct {
	Protocol uint8
	_        uint8 // matches compiler-inserted C padding
	DstPort  uint16
}

type ruleValue struct {
	Action     uint8
	_          [7]byte // padding to align match_count to 8 bytes
	MatchCount uint64
}

func validate(r Rule) error {
	if r.ID == "" {
		return fmt.Errorf("rule missing 'id'")
	}
	if _, ok := protoNumbers[r.Protocol]; !ok {
		return fmt.Errorf("rule %q: unknown protocol %q (use tcp/udp/icmp/any)", r.ID, r.Protocol)
	}
	if r.Action != "allow" && r.Action != "drop" {
		return fmt.Errorf("rule %q: action must be 'allow' or 'drop'", r.ID)
	}
	return nil
}

func loadRules(path string) (RuleFile, error) {
	var rf RuleFile
	data, err := os.ReadFile(path)
	if err != nil {
		return rf, fmt.Errorf("reading %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &rf); err != nil {
		return rf, fmt.Errorf("parsing %s: %w", path, err)
	}
	for _, r := range rf.Rules {
		if err := validate(r); err != nil {
			return rf, err
		}
	}
	return rf, nil
}

func applyRules(m *ebpf.Map, rf RuleFile) (int, error) {
	// Clear existing entries so removed rules stop taking effect.
	var key ruleKey
	var keys []ruleKey
	it := m.Iterate()
	for it.Next(&key, new(ruleValue)) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		_ = m.Delete(&k)
	}

	applied := 0
	for _, r := range rf.Rules {
		proto := protoNumbers[r.Protocol]
		action := actionAllow
		if r.Action == "drop" {
			action = actionDrop
		}
		k := ruleKey{Protocol: proto, DstPort: r.DstPort}
		v := ruleValue{Action: action}
		if err := m.Put(&k, &v); err != nil {
			return applied, fmt.Errorf("writing rule %q to map: %w", r.ID, err)
		}
		applied++
	}
	return applied, nil
}

func main() {
	rulesPath := flag.String("rules", "example_rules.json", "path to JSON rules file")
	statsInterval := flag.Duration("stats", 10*time.Second, "how often to re-check the rules file for changes (0 disables hot reload)")
	flag.Parse()

	m, err := ebpf.LoadPinnedMap(pinnedRulesMapPath, nil)
	if err != nil {
		log.Fatalf("opening pinned map at %s (is phase1-loader running?): %v", pinnedRulesMapPath, err)
	}
	defer m.Close()

	rf, err := loadRules(*rulesPath)
	if err != nil {
		log.Fatalf("loading rules: %v", err)
	}
	applied, err := applyRules(m, rf)
	if err != nil {
		log.Fatalf("applying rules: %v", err)
	}
	fmt.Printf(" Phase 3 rules manager: applied %d rules from %s\n", applied, *rulesPath)

	if *statsInterval <= 0 {
		return
	}

	fmt.Printf("   Watching %s for changes every %s (Ctrl+C to stop)\n", *rulesPath, *statsInterval)
	lastMod := fileModTime(*rulesPath)
	ticker := time.NewTicker(*statsInterval)
	defer ticker.Stop()
	for range ticker.C {
		mod := fileModTime(*rulesPath)
		if mod.After(lastMod) {
			newRf, err := loadRules(*rulesPath)
			if err != nil {
				log.Printf("  reload skipped, invalid rules file: %v", err)
				continue
			}
			n, err := applyRules(m, newRf)
			if err != nil {
				log.Printf("  reload failed: %v", err)
				continue
			}
			fmt.Printf("[%s]  reloaded %d rules (file changed)\n", time.Now().Format(time.RFC3339), n)
			lastMod = mod
		}
	}
}

func fileModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
