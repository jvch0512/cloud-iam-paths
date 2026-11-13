package iam

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestGlob(t *testing.T) {
	cases := []struct {
		p, s string
		fold bool
		want bool
	}{
		{"*", "anything", false, true},
		{"s3:Get*", "s3:GetObject", true, true},
		{"s3:get*", "S3:GetObject", true, true},
		{"s3:get*", "S3:GetObject", false, false},
		{"iam:*", "s3:GetObject", true, false},
		{"a?c", "abc", false, true},
		{"a?c", "ac", false, false},
		{"arn:aws:s3:::b/*/x", "arn:aws:s3:::b/y/z/x", false, true},
		{"*x*y*", "aaxbbyccc", false, true},
		{"*x*y*", "aaybbxcc", false, false},
		{"", "", false, true},
		{"", "a", false, false},
	}
	for _, c := range cases {
		if got := Glob(c.p, c.s, c.fold); got != c.want {
			t.Errorf("Glob(%q,%q,%v)=%v want %v", c.p, c.s, c.fold, got, c.want)
		}
	}
}

func parse(t *testing.T, s string) *Document {
	t.Helper()
	d, err := ParseDocument("p", json.RawMessage(s))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestParseScalarAndListForms(t *testing.T) {
	d := parse(t, `{"Statement":{"Effect":"Allow","Action":"s3:Get*","Resource":["a","b"]}}`)
	if len(d.Statements) != 1 || d.Statements[0].Actions[0] != "s3:Get*" || len(d.Statements[0].Resources) != 2 {
		t.Fatalf("%+v", d.Statements)
	}
}

func TestParseURLEncodedString(t *testing.T) {
	enc, _ := json.Marshal(url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`))
	d, err := ParseDocument("p", enc)
	if err != nil || !DocIsAdmin(d) {
		t.Fatalf("err=%v admin=%v", err, DocIsAdmin(d))
	}
}

func TestParseRejectsBadDocuments(t *testing.T) {
	for _, bad := range []string{
		`{"Statement":[{"Effect":"Maybe","Action":"*","Resource":"*"}]}`,
		`{"Statement":[{"Effect":"Allow","Action":5,"Resource":"*"}]}`,
		`{"Statement":"nope"}`,
		`[1]`,
		`"%zz"`,
	} {
		if _, err := ParseDocument("p", json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestEvaluate(t *testing.T) {
	allow := Statement{Effect: "Allow", Actions: []string{"iam:*"}, Resources: []string{"*"}, Policy: "A"}
	deny := Statement{Effect: "Deny", Actions: []string{"iam:Delete*"}, Resources: []string{"*"}, Policy: "D"}
	if d := Evaluate([]Statement{allow}, "iam:GetUser", "arn:x"); !d.Allowed || d.Conditional || d.Via != "A" {
		t.Errorf("%+v", d)
	}
	if d := Evaluate([]Statement{allow, deny}, "iam:DeleteUser", "arn:x"); d.Allowed {
		t.Error("explicit deny must win")
	}
	if d := Evaluate([]Statement{allow, deny}, "iam:GetUser", "arn:x"); !d.Allowed {
		t.Error("deny of other actions must not block")
	}
	cond := allow
	cond.HasCondition = true
	if d := Evaluate([]Statement{cond}, "iam:GetUser", "arn:x"); !d.Allowed || !d.Conditional {
		t.Errorf("%+v", d)
	}
	condDeny := deny
	condDeny.HasCondition = true
	if d := Evaluate([]Statement{allow, condDeny}, "iam:DeleteUser", "arn:x"); !d.Allowed {
		t.Error("conditional deny is ignored on purpose")
	}
	if d := Evaluate([]Statement{cond, allow}, "iam:GetUser", "arn:x"); d.Conditional {
		t.Error("an unconditional grant makes it certain")
	}
}

func TestNotActionAndNotResource(t *testing.T) {
	s := Statement{Effect: "Allow", NotActions: []string{"iam:*"}, Resources: []string{"*"}}
	if s.Matches("iam:GetUser", "x") || !s.Matches("s3:GetObject", "x") {
		t.Error("NotAction")
	}
	s = Statement{Effect: "Allow", Actions: []string{"*"}, NotResources: []string{"arn:secret/*"}}
	if s.Matches("s3:Get", "arn:secret/a") || !s.Matches("s3:Get", "arn:public/a") {
		t.Error("NotResource")
	}
}

func TestIsAdminNeedsEverythingEverywhere(t *testing.T) {
	yes := parse(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	scoped := parse(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::b/*"}]}`)
	svc := parse(t, `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`)
	cond := parse(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"x":"y"}}}]}`)
	if !DocIsAdmin(yes) || DocIsAdmin(scoped) || DocIsAdmin(svc) || DocIsAdmin(cond) || DocIsAdmin(nil) {
		t.Error("admin detection")
	}
}

func TestLoadErrors(t *testing.T) {
	for _, bad := range []string{``, `{`, `{}`, `{"UserDetailList":[{"UserName":"a","Arn":"arn:aws:iam::1:user/a","UserPolicyList":[{"PolicyName":"x","PolicyDocument":{"Statement":[{"Effect":"X"}]}}]}]}`} {
		if _, err := Load([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestGroupPoliciesApplyToUsers(t *testing.T) {
	a, err := Load([]byte(`{"UserDetailList":[{"UserName":"u","Arn":"arn:aws:iam::1:user/u","GroupList":["g"]}],
	  "GroupDetailList":[{"GroupName":"g","Arn":"arn:aws:iam::1:group/g","GroupPolicyList":[{"PolicyName":"p","PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "1" || !a.Can(a.Principals[0], "s3:GetObject", "x").Allowed {
		t.Error("group inheritance")
	}
}
