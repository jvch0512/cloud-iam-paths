// Package graph finds privilege escalation paths: chains of IAM actions that turn a principal's
// permissions into administrator access.
package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jvch0512/cloud-iam-paths/internal/iam"
)

// Admin is the virtual goal node.
const Admin = "*ADMIN*"

// Edge is one step: From can become To by using the listed permissions.
type Edge struct {
	From        string   `json:"from"`
	To          string   `json:"to"`
	Technique   string   `json:"technique"`
	Needs       []string `json:"needs"`
	Explanation string   `json:"explanation"`
	Conditional bool     `json:"conditional,omitempty"`
}

// Path is the shortest chain from a principal to administrator access.
type Path struct {
	From        string `json:"from"`
	Kind        string `json:"kind"`
	Steps       []Edge `json:"steps"`
	Conditional bool   `json:"conditional,omitempty"`
}

// Finding is a standalone observation that is not a path.
type Finding struct {
	Severity string `json:"severity"`
	Subject  string `json:"subject"`
	Message  string `json:"message"`
}

// Result is the full analysis.
type Result struct {
	Account    string    `json:"account"`
	Principals int       `json:"principals"`
	Admins     []string  `json:"admins"`
	Paths      []Path    `json:"paths"`
	Safe       []string  `json:"no_path"`
	Findings   []Finding `json:"findings"`
	Edges      []Edge    `json:"-"`
}

var passRoleServices = []struct {
	service string
	needs   []string
	how     string
}{
	{"ec2.amazonaws.com", []string{"ec2:RunInstances"}, "launch an instance with the role attached, then read its credentials from the metadata service"},
	{"lambda.amazonaws.com", []string{"lambda:CreateFunction", "lambda:InvokeFunction"}, "create and invoke a Lambda function that runs as the role"},
	{"cloudformation.amazonaws.com", []string{"cloudformation:CreateStack"}, "create a stack that CloudFormation deploys with the role"},
	{"glue.amazonaws.com", []string{"glue:CreateDevEndpoint"}, "create a Glue dev endpoint with the role and log in to it"},
	{"sagemaker.amazonaws.com", []string{"sagemaker:CreateNotebookInstance"}, "create a notebook instance with the role and open its terminal"},
}

type builder struct {
	a     *iam.Account
	edges []Edge
	seen  map[string]bool
}

func (b *builder) add(e Edge) {
	k := e.From + "|" + e.To + "|" + e.Technique
	if b.seen[k] || e.From == e.To {
		return
	}
	b.seen[k] = true
	b.edges = append(b.edges, e)
}

// check evaluates every (action, resource) pair and reports whether all are allowed.
func (b *builder) check(p *iam.Principal, actions []string, resource string) (ok, conditional bool) {
	for _, act := range actions {
		d := b.a.Can(p, act, resource)
		if !d.Allowed {
			return false, false
		}
		conditional = conditional || d.Conditional
	}
	return true, conditional
}

func needsText(actions []string, resource string) []string {
	out := make([]string, len(actions))
	for i, a := range actions {
		out[i] = a + " on " + resource
	}
	return out
}

func (b *builder) trustAllows(role *iam.Principal, who *iam.Principal, service string) (allowed, needsIdentityGrant, conditional bool) {
	for _, s := range role.Trust.Statements {
		if s.Effect != "Allow" {
			continue
		}
		for _, pr := range s.Principals {
			switch {
			case service != "" && strings.EqualFold(pr, service):
				return true, false, s.HasCondition
			case who != nil && pr == who.ARN:
				return true, false, s.HasCondition
			case who != nil && (pr == "*" || pr == "arn:aws:iam::"+b.a.ID+":root"):
				allowed, needsIdentityGrant, conditional = true, true, s.HasCondition
			}
		}
	}
	return
}

func (b *builder) build() {
	a := b.a
	for _, p := range a.Principals {
		if a.IsAdmin(p) {
			continue
		}
		// permissions that rewrite policies attached to the principal
		for _, arn := range managedPolicies(a, p) {
			m := a.Policies[arn]
			if ok, c := b.check(p, []string{"iam:CreatePolicyVersion"}, arn); ok {
				b.add(Edge{p.ARN, Admin, "CreatePolicyVersion", needsText([]string{"iam:CreatePolicyVersion"}, arn), fmt.Sprintf("Publish a new default version of the attached policy %s that allows everything.", m.Name), c})
			}
			if ok, c := b.check(p, []string{"iam:SetDefaultPolicyVersion"}, arn); ok {
				for _, v := range m.Versions {
					if !v.Default && iam.DocIsAdmin(v.Doc) {
						b.add(Edge{p.ARN, Admin, "SetDefaultPolicyVersion", needsText([]string{"iam:SetDefaultPolicyVersion"}, arn), fmt.Sprintf("Switch %s back to its older version %s, which allows everything.", m.Name, v.ID), c})
					}
				}
			}
		}
		if p.Kind == "user" {
			for _, act := range []string{"iam:AttachUserPolicy", "iam:PutUserPolicy"} {
				if ok, c := b.check(p, []string{act}, p.ARN); ok {
					b.add(Edge{p.ARN, Admin, strings.TrimPrefix(act, "iam:"), needsText([]string{act}, p.ARN), "Attach or write an administrator policy on their own user.", c})
				}
			}
			for _, gn := range p.Groups {
				if g := a.Groups[gn]; g != nil {
					for _, act := range []string{"iam:AttachGroupPolicy", "iam:PutGroupPolicy"} {
						if ok, c := b.check(p, []string{act}, g.ARN); ok {
							b.add(Edge{p.ARN, Admin, strings.TrimPrefix(act, "iam:"), needsText([]string{act}, g.ARN), fmt.Sprintf("Add an administrator policy to the group %s they already belong to.", g.Name), c})
						}
					}
				}
			}
			for _, g := range sortedGroups(a) {
				if a.GroupIsAdmin(g) && !contains(p.Groups, g.Name) {
					if ok, c := b.check(p, []string{"iam:AddUserToGroup"}, g.ARN); ok {
						b.add(Edge{p.ARN, Admin, "AddUserToGroup", needsText([]string{"iam:AddUserToGroup"}, g.ARN), fmt.Sprintf("Add themselves to the administrator group %s.", g.Name), c})
					}
				}
			}
		}
		if p.Kind == "role" {
			for _, act := range []string{"iam:AttachRolePolicy", "iam:PutRolePolicy"} {
				if ok, c := b.check(p, []string{act}, p.ARN); ok {
					b.add(Edge{p.ARN, Admin, strings.TrimPrefix(act, "iam:"), needsText([]string{act}, p.ARN), "Attach or write an administrator policy on this role itself.", c})
				}
			}
		}
		for _, t := range a.Principals {
			if t.ARN == p.ARN {
				continue
			}
			if t.Kind == "user" {
				for _, act := range []string{"iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"} {
					if ok, c := b.check(p, []string{act}, t.ARN); ok {
						b.add(Edge{p.ARN, t.ARN, strings.TrimPrefix(act, "iam:"), needsText([]string{act}, t.ARN), fmt.Sprintf("Create credentials for %s and sign in as them.", t.Name), c})
					}
				}
				continue
			}
			// roles
			if allowed, needGrant, tc := b.trustAllows(t, p, ""); allowed {
				ok, c := true, false
				if needGrant {
					ok, c = b.check(p, []string{"sts:AssumeRole"}, t.ARN)
				}
				if ok {
					b.add(Edge{p.ARN, t.ARN, "AssumeRole", needsText([]string{"sts:AssumeRole"}, t.ARN), fmt.Sprintf("Assume the role %s, whose trust policy allows them.", t.Name), c || tc})
				}
			}
			if ok, c := b.check(p, []string{"iam:UpdateAssumeRolePolicy"}, t.ARN); ok {
				b.add(Edge{p.ARN, t.ARN, "UpdateAssumeRolePolicy", needsText([]string{"iam:UpdateAssumeRolePolicy"}, t.ARN), fmt.Sprintf("Rewrite the trust policy of %s to trust them, then assume it.", t.Name), c})
			}
			if ok, pc := b.check(p, []string{"iam:PassRole"}, t.ARN); ok {
				for _, svc := range passRoleServices {
					if allowed, _, _ := b.trustAllows(t, nil, svc.service); !allowed {
						continue
					}
					if ok2, c2 := b.check(p, svc.needs, "*"); ok2 {
						b.add(Edge{p.ARN, t.ARN, "PassRole+" + strings.Split(svc.needs[0], ":")[0], append(needsText([]string{"iam:PassRole"}, t.ARN), svc.needs...), fmt.Sprintf("Pass %s to %s and %s.", t.Name, strings.Split(svc.service, ".")[0], svc.how), pc || c2})
					}
				}
			}
		}
	}
	// a role that can be assumed and that can edit its own policies reaches admin
	for _, e := range append([]Edge(nil), b.edges...) {
		t := a.ByARN(e.To)
		if t == nil || t.Kind != "role" {
			continue
		}
		src := a.ByARN(e.From)
		for _, act := range []string{"iam:AttachRolePolicy", "iam:PutRolePolicy"} {
			if ok, c := b.check(src, []string{act}, t.ARN); ok && !a.IsAdmin(src) {
				b.add(Edge{e.From, Admin, strings.TrimPrefix(act, "iam:"), needsText([]string{act}, t.ARN), fmt.Sprintf("Attach an administrator policy to %s, a role they can already use.", t.Name), c || e.Conditional})
			}
		}
	}
}

func managedPolicies(a *iam.Account, p *iam.Principal) []string {
	seen := map[string]bool{}
	var out []string
	add := func(l []string) {
		for _, x := range l {
			if !seen[x] && a.Policies[x] != nil {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	add(p.Attached)
	for _, gn := range p.Groups {
		if g := a.Groups[gn]; g != nil {
			add(g.Attached)
		}
	}
	return out
}

func sortedGroups(a *iam.Account) []*iam.Group {
	var out []*iam.Group
	for _, g := range a.Groups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Analyse builds the escalation graph and finds the shortest path to admin for every non-admin principal.
func Analyse(a *iam.Account) *Result {
	b := &builder{a: a, seen: map[string]bool{}}
	b.build()
	res := &Result{Account: a.ID, Principals: len(a.Principals), Edges: b.edges, Paths: []Path{}, Admins: []string{}, Safe: []string{}, Findings: []Finding{}}
	adj := map[string][]Edge{}
	for _, e := range b.edges {
		adj[e.From] = append(adj[e.From], e)
	}
	admin := map[string]bool{}
	for _, p := range a.Principals {
		if a.IsAdmin(p) {
			admin[p.ARN] = true
			res.Admins = append(res.Admins, p.Name)
		}
	}
	for _, p := range a.Principals {
		if admin[p.ARN] {
			continue
		}
		if steps := shortest(p.ARN, adj, admin); steps != nil {
			path := Path{From: p.Name, Kind: p.Kind, Steps: steps}
			for _, s := range steps {
				path.Conditional = path.Conditional || s.Conditional
			}
			res.Paths = append(res.Paths, path)
		} else {
			res.Safe = append(res.Safe, p.Name)
		}
	}
	sort.SliceStable(res.Paths, func(i, j int) bool {
		if len(res.Paths[i].Steps) != len(res.Paths[j].Steps) {
			return len(res.Paths[i].Steps) < len(res.Paths[j].Steps)
		}
		return res.Paths[i].From < res.Paths[j].From
	})
	res.Findings = findings(a)
	return res
}

// shortest runs a breadth-first search over principals; nodes that are admin end the search.
func shortest(start string, adj map[string][]Edge, admin map[string]bool) []Edge {
	type item struct {
		node string
		path []Edge
	}
	seen := map[string]bool{start: true}
	queue := []item{{node: start}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range adj[cur.node] {
			next := append(append([]Edge(nil), cur.path...), e)
			if e.To == Admin || admin[e.To] {
				return next
			}
			if !seen[e.To] {
				seen[e.To] = true
				queue = append(queue, item{e.To, next})
			}
		}
	}
	return nil
}

func findings(a *iam.Account) []Finding {
	var out []Finding
	for _, p := range a.Principals {
		if p.Kind == "role" {
			for _, s := range p.Trust.Statements {
				if s.Effect != "Allow" {
					continue
				}
				for _, pr := range s.Principals {
					if pr == "*" && !s.HasCondition {
						out = append(out, Finding{"high", p.Name, "Trust policy allows any principal (\"*\") to assume this role with no condition."})
					}
				}
			}
		}
		if p.Kind == "user" && a.IsAdmin(p) {
			out = append(out, Finding{"info", p.Name, "User has administrator access directly; prefer a role that is assumed with MFA."})
		}
	}
	return out
}
