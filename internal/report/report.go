// Package report renders an analysis as text, Markdown, JSON or Graphviz.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jvch0512/cloud-iam-paths/internal/graph"
)

func short(arn string) string {
	if arn == graph.Admin {
		return "ADMIN"
	}
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Text is the console report.
func Text(r *graph.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Account %s: %s, %s with a path to administrator access, %s without\n\n",
		r.Account, plural(r.Principals, "principal", "principals"), plural(len(r.Paths), "principal", "principals"), plural(len(r.Safe), "principal", "principals"))
	for _, p := range r.Paths {
		note := ""
		if p.Conditional {
			note = "  [depends on a policy condition]"
		}
		fmt.Fprintf(&b, "%s (%s): %s to admin%s\n", p.From, p.Kind, plural(len(p.Steps), "step", "steps"), note)
		for i, s := range p.Steps {
			fmt.Fprintf(&b, "  %d. %s -> %s  [%s]\n     %s\n     needs: %s\n", i+1, short(s.From), short(s.To), s.Technique, s.Explanation, strings.Join(s.Needs, ", "))
		}
		b.WriteString("\n")
	}
	if len(r.Admins) > 0 {
		fmt.Fprintf(&b, "Already administrators: %s\n", strings.Join(r.Admins, ", "))
	}
	if len(r.Safe) > 0 {
		fmt.Fprintf(&b, "No escalation path found: %s\n", strings.Join(r.Safe, ", "))
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "[%s] %s: %s\n", f.Severity, f.Subject, f.Message)
	}
	return b.String()
}

// Markdown is a shareable report.
func Markdown(r *graph.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# IAM privilege escalation report\n\nAccount `%s`. **%d of %d principals** can reach administrator access.\n\n", r.Account, len(r.Paths), r.Principals)
	if len(r.Paths) > 0 {
		b.WriteString("| Principal | Kind | Steps | Route |\n|---|---|---|---|\n")
		for _, p := range r.Paths {
			var hops []string
			for _, s := range p.Steps {
				hops = append(hops, fmt.Sprintf("%s (%s)", short(s.To), s.Technique))
			}
			fmt.Fprintf(&b, "| %s | %s | %d | %s |\n", p.From, p.Kind, len(p.Steps), strings.Join(hops, " -> "))
		}
		b.WriteString("\n## Details\n\n")
		for _, p := range r.Paths {
			fmt.Fprintf(&b, "### %s\n\n", p.From)
			for i, s := range p.Steps {
				fmt.Fprintf(&b, "%d. **%s**: %s\n   - needs: %s\n", i+1, s.Technique, s.Explanation, "`"+strings.Join(s.Needs, "`, `")+"`")
			}
			b.WriteString("\n")
		}
	}
	if len(r.Safe) > 0 {
		fmt.Fprintf(&b, "No path found for: %s.\n\n", strings.Join(r.Safe, ", "))
	}
	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "- **%s** `%s`: %s\n", f.Severity, f.Subject, f.Message)
		}
	}
	b.WriteString("\nThis analysis reads identity and trust policies only. Service control policies, permission boundaries, session policies, resource policies and most conditions are not evaluated, so treat results as candidates to verify.\n")
	return b.String()
}

// JSON is the machine-readable report.
func JSON(r *graph.Result) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// DOT draws the escalation paths as a Graphviz graph.
func DOT(r *graph.Result) string {
	var b strings.Builder
	b.WriteString("digraph iam {\n  rankdir=LR;\n  node [shape=box, fontname=\"Helvetica\"];\n  \"ADMIN\" [style=filled, fillcolor=\"#f8d7da\", fontcolor=\"#000000\"];\n")
	admins := append([]string(nil), r.Admins...)
	sort.Strings(admins)
	for _, a := range admins {
		fmt.Fprintf(&b, "  %q [style=filled, fillcolor=\"#f8d7da\", fontcolor=\"#000000\"];\n", a)
	}
	seen := map[string]bool{}
	var lines []string
	for _, p := range r.Paths {
		for _, s := range p.Steps {
			l := fmt.Sprintf("  %q -> %q [label=%q];", short(s.From), short(s.To), s.Technique)
			if !seen[l] {
				seen[l] = true
				lines = append(lines, l)
			}
		}
	}
	sort.Strings(lines)
	b.WriteString(strings.Join(lines, "\n"))
	b.WriteString("\n}\n")
	return b.String()
}
