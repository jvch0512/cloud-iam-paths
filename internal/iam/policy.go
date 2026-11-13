// Package iam reads an AWS IAM authorization export and answers "can this principal do X on Y".
package iam

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Statement is one IAM policy statement, normalised so scalar and list forms look the same.
type Statement struct {
	Effect       string
	Actions      []string
	NotActions   []string
	Resources    []string
	NotResources []string
	Principals   []string // only meaningful in trust policies: ARNs, "*" or service names
	HasCondition bool
	Policy       string // name of the policy it came from
}

// Document is a parsed policy document.
type Document struct {
	Name       string
	Statements []Statement
}

type rawStatement struct {
	Effect      string          `json:"Effect"`
	Action      json.RawMessage `json:"Action"`
	NotAction   json.RawMessage `json:"NotAction"`
	Resource    json.RawMessage `json:"Resource"`
	NotResource json.RawMessage `json:"NotResource"`
	Principal   json.RawMessage `json:"Principal"`
	Condition   json.RawMessage `json:"Condition"`
}

// stringList accepts "a" or ["a","b"].
func stringList(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("expected a string or list of strings, got %s", truncate(string(raw), 40))
	}
	return many, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func principals(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var star string
	if json.Unmarshal(raw, &star) == nil {
		return []string{star}, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("bad Principal")
	}
	var out []string
	for _, v := range m {
		l, err := stringList(v)
		if err != nil {
			return nil, err
		}
		out = append(out, l...)
	}
	return out, nil
}

// ParseDocument accepts a decoded JSON object, or the URL-encoded string form the raw API returns.
func ParseDocument(name string, raw json.RawMessage) (*Document, error) {
	var asString string
	if json.Unmarshal(raw, &asString) == nil {
		dec, err := url.QueryUnescape(asString)
		if err != nil {
			return nil, fmt.Errorf("policy %q: bad URL encoding", name)
		}
		raw = json.RawMessage(dec)
	}
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("policy %q: %w", name, err)
	}
	var list []rawStatement
	if err := json.Unmarshal(doc.Statement, &list); err != nil {
		var one rawStatement
		if err2 := json.Unmarshal(doc.Statement, &one); err2 != nil {
			return nil, fmt.Errorf("policy %q: bad Statement", name)
		}
		list = []rawStatement{one}
	}
	d := &Document{Name: name}
	for i, rs := range list {
		if rs.Effect != "Allow" && rs.Effect != "Deny" {
			return nil, fmt.Errorf("policy %q statement %d: Effect must be Allow or Deny", name, i+1)
		}
		s := Statement{Effect: rs.Effect, Policy: name}
		var err error
		if s.Actions, err = stringList(rs.Action); err != nil {
			return nil, fmt.Errorf("policy %q statement %d Action: %w", name, i+1, err)
		}
		if s.NotActions, err = stringList(rs.NotAction); err != nil {
			return nil, fmt.Errorf("policy %q statement %d NotAction: %w", name, i+1, err)
		}
		if s.Resources, err = stringList(rs.Resource); err != nil {
			return nil, fmt.Errorf("policy %q statement %d Resource: %w", name, i+1, err)
		}
		if s.NotResources, err = stringList(rs.NotResource); err != nil {
			return nil, fmt.Errorf("policy %q statement %d NotResource: %w", name, i+1, err)
		}
		if s.Principals, err = principals(rs.Principal); err != nil {
			return nil, fmt.Errorf("policy %q statement %d: %w", name, i+1, err)
		}
		c := strings.TrimSpace(string(rs.Condition))
		s.HasCondition = c != "" && c != "null" && c != "{}"
		d.Statements = append(d.Statements, s)
	}
	return d, nil
}

// Glob matches IAM-style patterns: * is any run, ? is one character.
func Glob(pattern, s string, foldCase bool) bool {
	if foldCase {
		pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	}
	p, t := []rune(pattern), []rune(s)
	pi, ti, star, mark := 0, 0, -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]) && p[pi] != '*':
			pi++
			ti++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func anyGlob(patterns []string, s string, fold bool) bool {
	for _, p := range patterns {
		if Glob(p, s, fold) {
			return true
		}
	}
	return false
}

// Matches reports whether the statement's Action and Resource scope covers the request.
func (s Statement) Matches(action, resource string) bool {
	if len(s.NotActions) > 0 {
		if anyGlob(s.NotActions, action, true) {
			return false
		}
	} else if !anyGlob(s.Actions, action, true) {
		return false
	}
	if len(s.NotResources) > 0 {
		return !anyGlob(s.NotResources, resource, false)
	}
	return anyGlob(s.Resources, resource, false)
}

// Decision is the outcome of evaluating one request against a set of statements.
type Decision struct {
	Allowed     bool
	Conditional bool   // every matching Allow carries a Condition, so the grant is not certain
	Via         string // policy that granted it
}

// Evaluate applies explicit-deny-wins. An unconditional matching Deny blocks the request.
// A Deny with a Condition is ignored, because whether it applies depends on the runtime context;
// that choice leans towards reporting a path, never towards hiding one.
func Evaluate(stmts []Statement, action, resource string) Decision {
	var d Decision
	certain := false
	for _, s := range stmts {
		if s.Effect == "Deny" && !s.HasCondition && s.Matches(action, resource) {
			return Decision{}
		}
	}
	for _, s := range stmts {
		if s.Effect == "Allow" && s.Matches(action, resource) {
			if !d.Allowed {
				d.Via = s.Policy
			}
			d.Allowed = true
			if !s.HasCondition {
				certain = true
				d.Via = s.Policy
			}
		}
	}
	d.Conditional = d.Allowed && !certain
	return d
}
