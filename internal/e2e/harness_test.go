package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPredeclaredNamesStayInSync(t *testing.T) {
	h := New(Options{}, nil)
	actual := h.builtins()
	declared := names()
	if len(actual) != len(declared) {
		t.Fatalf("builtins %d, declared %d", len(actual), len(declared))
	}
	for name := range actual {
		if !declared[name] {
			t.Errorf("%s absent from static gate", name)
		}
	}
}

func TestCheckRejectsUnknownBuiltin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.star")
	if err := os.WriteFile(path, []byte("shell(\"echo unsupported\")\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Check(path); err == nil {
		t.Fatal("unknown builtin accepted")
	}
}

func TestCheckValidatesLoadedModule(t *testing.T) {
	root := t.TempDir()
	scenario := filepath.Join(root, "scenario.star")
	module := filepath.Join(root, "common.star")
	if err := os.WriteFile(scenario, []byte("load(\"common.star\", \"helper\")\nhelper()\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module, []byte("def helper():\n    unsupported()\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Check(scenario); err == nil {
		t.Fatal("invalid loaded module passed the static check")
	}
}
