package iam

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Principal is a user or a role.
type Principal struct {
	Kind     string // "user" or "role"
	Name     string
	ARN      string
	Groups   []string
	Attached []string // managed policy ARNs
	Inline   []*Document
	Trust    *Document // roles only
}

type Group struct {
	Name     string
	ARN      string
	Attached []string
	Inline   []*Document
}

type PolicyVersion struct {
	ID      string
	Default bool
	Doc     *Document
}

type Managed struct {
	Name     string
	ARN      string
	Versions []PolicyVersion
}

// Default returns the default version document.
func (m *Managed) Default() *Document {
	for _, v := range m.Versions {
		if v.Default {
			return v.Doc
		}
	}
	return nil
}

type Account struct {
	ID         string
	Principals []*Principal
	Groups     map[string]*Group
	Policies   map[string]*Managed
	byARN      map[string]*Principal
}

type attached struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type named struct {
	PolicyName     string          `json:"PolicyName"`
	PolicyDocument json.RawMessage `json:"PolicyDocument"`
}

type exportFile struct {
	Users []struct {
		UserName string     `json:"UserName"`
		Arn      string     `json:"Arn"`
		Inline   []named    `json:"UserPolicyList"`
		Groups   []string   `json:"GroupList"`
		Attached []attached `json:"AttachedManagedPolicies"`
	} `json:"UserDetailList"`
	Groups []struct {
		GroupName string     `json:"GroupName"`
		Arn       string     `json:"Arn"`
		Inline    []named    `json:"GroupPolicyList"`
		Attached  []attached `json:"AttachedManagedPolicies"`
	} `json:"GroupDetailList"`
	Roles []struct {
		RoleName string          `json:"RoleName"`
		Arn      string          `json:"Arn"`
		Trust    json.RawMessage `json:"AssumeRolePolicyDocument"`
		Inline   []named         `json:"RolePolicyList"`
		Attached []attached      `json:"AttachedManagedPolicies"`
	} `json:"RoleDetailList"`
	Policies []struct {
		PolicyName string `json:"PolicyName"`
		Arn        string `json:"Arn"`
		Versions   []struct {
			Document  json.RawMessage `json:"Document"`
			VersionID string          `json:"VersionId"`
			Default   bool            `json:"IsDefaultVersion"`
		} `json:"PolicyVersionList"`
	} `json:"Policies"`
}

func inlineDocs(in []named) ([]*Document, error) {
	var out []*Document
	for _, n := range in {
		d, err := ParseDocument(n.PolicyName, n.PolicyDocument)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func arns(a []attached) []string {
	var out []string
	for _, x := range a {
		out = append(out, x.PolicyArn)
	}
	return out
}

// Load parses the output of `aws iam get-account-authorization-details`.
func Load(data []byte) (*Account, error) {
	var f exportFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("not a valid IAM export: %w", err)
	}
	if len(f.Users)+len(f.Roles)+len(f.Groups) == 0 {
		return nil, fmt.Errorf("export has no users, roles or groups (expected UserDetailList, GroupDetailList, RoleDetailList)")
	}
	a := &Account{Groups: map[string]*Group{}, Policies: map[string]*Managed{}, byARN: map[string]*Principal{}}
	for _, p := range f.Policies {
		m := &Managed{Name: p.PolicyName, ARN: p.Arn}
		for _, v := range p.Versions {
			d, err := ParseDocument(p.PolicyName, v.Document)
			if err != nil {
				return nil, err
			}
			m.Versions = append(m.Versions, PolicyVersion{ID: v.VersionID, Default: v.Default, Doc: d})
		}
		a.Policies[p.Arn] = m
	}
	for _, g := range f.Groups {
		in, err := inlineDocs(g.Inline)
		if err != nil {
			return nil, err
		}
		a.Groups[g.GroupName] = &Group{Name: g.GroupName, ARN: g.Arn, Attached: arns(g.Attached), Inline: in}
	}
	for _, u := range f.Users {
		in, err := inlineDocs(u.Inline)
		if err != nil {
			return nil, err
		}
		a.add(&Principal{Kind: "user", Name: u.UserName, ARN: u.Arn, Groups: u.Groups, Attached: arns(u.Attached), Inline: in})
	}
	for _, r := range f.Roles {
		in, err := inlineDocs(r.Inline)
		if err != nil {
			return nil, err
		}
		trust, err := ParseDocument(r.RoleName+" (trust policy)", r.Trust)
		if err != nil {
			return nil, err
		}
		a.add(&Principal{Kind: "role", Name: r.RoleName, ARN: r.Arn, Attached: arns(r.Attached), Inline: in, Trust: trust})
	}
	sort.Slice(a.Principals, func(i, j int) bool { return a.Principals[i].ARN < a.Principals[j].ARN })
	for _, p := range a.Principals {
		if parts := strings.Split(p.ARN, ":"); len(parts) > 4 && a.ID == "" {
			a.ID = parts[4]
		}
	}
	return a, nil
}

func (a *Account) add(p *Principal) {
	a.Principals = append(a.Principals, p)
	a.byARN[p.ARN] = p
}

// ByARN finds a principal.
func (a *Account) ByARN(arn string) *Principal { return a.byARN[arn] }

// Statements returns every statement that applies to the principal: inline, attached and via groups.
func (a *Account) Statements(p *Principal) []Statement {
	var out []Statement
	add := func(d *Document) {
		if d != nil {
			out = append(out, d.Statements...)
		}
	}
	for _, d := range p.Inline {
		add(d)
	}
	for _, arn := range p.Attached {
		if m := a.Policies[arn]; m != nil {
			add(m.Default())
		}
	}
	for _, gn := range p.Groups {
		if g := a.Groups[gn]; g != nil {
			for _, d := range g.Inline {
				add(d)
			}
			for _, arn := range g.Attached {
				if m := a.Policies[arn]; m != nil {
					add(m.Default())
				}
			}
		}
	}
	return out
}

// GroupStatements returns the statements that apply to a group.
func (a *Account) GroupStatements(g *Group) []Statement {
	var out []Statement
	for _, d := range g.Inline {
		out = append(out, d.Statements...)
	}
	for _, arn := range g.Attached {
		if m := a.Policies[arn]; m != nil && m.Default() != nil {
			out = append(out, m.Default().Statements...)
		}
	}
	return out
}

// Can evaluates one request for a principal.
func (a *Account) Can(p *Principal, action, resource string) Decision {
	return Evaluate(a.Statements(p), action, resource)
}

// probe is an action and resource no real policy names, used to detect "Action: *, Resource: *".
const (
	probeAction   = "zz:Everything"
	probeResource = "arn:aws:zz:::everything"
)

// IsAdmin is true when the principal is allowed everything.
func (a *Account) IsAdmin(p *Principal) bool {
	d := Evaluate(a.Statements(p), probeAction, probeResource)
	return d.Allowed && !d.Conditional
}

// GroupIsAdmin is IsAdmin for a group.
func (a *Account) GroupIsAdmin(g *Group) bool {
	d := Evaluate(a.GroupStatements(g), probeAction, probeResource)
	return d.Allowed && !d.Conditional
}

// DocIsAdmin reports whether a policy document grants everything.
func DocIsAdmin(d *Document) bool {
	if d == nil {
		return false
	}
	x := Evaluate(d.Statements, probeAction, probeResource)
	return x.Allowed && !x.Conditional
}
