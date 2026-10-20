package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadRulesTightensPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	body := []byte(`{"rules":[{"id":"ssh","protocol":"tcp","dst_port":22,"action":"allow"}]}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRules(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != rulesFilePerm {
		t.Fatalf("rules file mode = %o, want %o", info.Mode().Perm(), rulesFilePerm)
	}
}
