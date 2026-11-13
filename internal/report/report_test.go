package report

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jvch0512/cloud-iam-paths/internal/graph"
	"github.com/jvch0512/cloud-iam-paths/internal/iam"
)

func result(t *testing.T) *graph.Result {
	t.Helper()
	data, err := os.ReadFile("../../examples/account.json")
	if err != nil {
		t.Fatal(err)
	}
	a, err := iam.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	return graph.Analyse(a)
}

func TestJSONRoundTrips(t *testing.T) {
	b, err := JSON(result(t))
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Account string `json:"account"`
		Paths   []struct {
			From  string `json:"from"`
			Steps []struct {
				Technique string `json:"technique"`
			} `json:"steps"`
		} `json:"paths"`
		NoPath []string `json:"no_path"`
	}
	if err := json.Unmarshal(b, &back); err != nil || back.Account != "111122223333" || len(back.Paths) != 9 || len(back.NoPath) != 3 {
		t.Fatalf("err=%v %+v", err, back)
	}
}

func TestTextAndMarkdownMentionEveryPath(t *testing.T) {
	r := result(t)
	text, md := Text(r), Markdown(r)
	for _, p := range r.Paths {
		if !strings.Contains(text, p.From+" (") || !strings.Contains(md, "### "+p.From) {
			t.Errorf("%s missing from output", p.From)
		}
	}
	if !strings.Contains(md, "Service control policies") {
		t.Error("the limits note must be in the report")
	}
}

func TestDOTIsDeterministicAndDeduplicated(t *testing.T) {
	r := result(t)
	a, b := DOT(r), DOT(r)
	if a != b {
		t.Fatal("DOT output must be stable")
	}
	if strings.Count(a, `"build-role" -> "ADMIN"`) != 1 {
		t.Error("duplicate edges")
	}
	if !strings.HasPrefix(a, "digraph iam {") || !strings.HasSuffix(a, "}\n") {
		t.Error("shape")
	}
}
