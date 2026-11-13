package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = "../../examples/account.json"

func exec(args ...string) (int, string, string) {
	var o, e bytes.Buffer
	code := run(args, &o, &e)
	return code, o.String(), e.String()
}

func TestRunOutputsAndExitCodes(t *testing.T) {
	dir := t.TempDir()
	j, m, d := filepath.Join(dir, "a.json"), filepath.Join(dir, "a.md"), filepath.Join(dir, "a.dot")
	code, out, _ := exec("-json", j, "-md", m, "-dot", d, fixture)
	if code != 0 || !strings.Contains(out, "alice (user): 1 step to admin") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	for f, want := range map[string]string{j: `"technique": "CreatePolicyVersion"`, m: "# IAM privilege escalation report", d: `"alice" -> "ADMIN"`} {
		b, err := os.ReadFile(f)
		if err != nil || !strings.Contains(string(b), want) {
			t.Errorf("%s missing %q (err %v)", f, want, err)
		}
	}
	if code, _, _ := exec("-fail-on-path", fixture); code != 1 {
		t.Errorf("fail-on-path should exit 1, got %d", code)
	}
}

func TestRunErrors(t *testing.T) {
	if code, _, _ := exec(); code != 2 {
		t.Error("no args")
	}
	if code, _, e := exec("/nonexistent.json"); code != 2 || e == "" {
		t.Error("missing file")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte("{not json"), 0o600)
	if code, _, e := exec(bad); code != 2 || !strings.Contains(e, "not a valid IAM export") {
		t.Errorf("bad json: %d %s", code, e)
	}
	if code, _, _ := exec("-nope", fixture); code != 2 {
		t.Error("unknown flag")
	}
}

func TestCleanAccountExitsZeroEvenWithFailOnPath(t *testing.T) {
	f := filepath.Join(t.TempDir(), "ok.json")
	os.WriteFile(f, []byte(`{"UserDetailList":[{"UserName":"g","Arn":"arn:aws:iam::1:user/g"}]}`), 0o600)
	if code, out, _ := exec("-fail-on-path", f); code != 0 || !strings.Contains(out, "0 principals with a path") {
		t.Errorf("%d %s", code, out)
	}
}
