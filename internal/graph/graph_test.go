package graph

import (
	"os"
	"strings"
	"testing"

	"github.com/jvch0512/cloud-iam-paths/internal/iam"
)

func load(t *testing.T, s string) *Result {
	t.Helper()
	a, err := iam.Load([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return Analyse(a)
}

func fixture(t *testing.T) *Result {
	t.Helper()
	data, err := os.ReadFile("../../examples/account.json")
	if err != nil {
		t.Fatal(err)
	}
	return load(t, string(data))
}

func pathOf(r *Result, name string) *Path {
	for i := range r.Paths {
		if r.Paths[i].From == name {
			return &r.Paths[i]
		}
	}
	return nil
}

func TestEachTechniqueInTheFixture(t *testing.T) {
	r := fixture(t)
	want := map[string]string{
		"alice": "CreatePolicyVersion", "bob": "PassRole+lambda", "carol": "AddUserToGroup", "erin": "CreateAccessKey",
		"ivan": "UpdateAssumeRolePolicy", "kim": "SetDefaultPolicyVersion", "leo": "AttachUserPolicy", "build-role": "AttachRolePolicy",
	}
	for who, tech := range want {
		p := pathOf(r, who)
		if p == nil {
			t.Errorf("%s: no path found", who)
			continue
		}
		if p.Steps[0].Technique != tech {
			t.Errorf("%s: technique %s, want %s", who, p.Steps[0].Technique, tech)
		}
	}
}

func TestChainsAreFound(t *testing.T) {
	p := pathOf(fixture(t), "frank")
	if p == nil || len(p.Steps) != 2 || p.Steps[0].Technique != "AssumeRole" || p.Steps[1].Technique != "AttachRolePolicy" {
		t.Fatalf("%+v", p)
	}
}

func TestNoFalsePositives(t *testing.T) {
	r := fixture(t)
	for _, n := range []string{"grace", "heidi", "public-role"} {
		if pathOf(r, n) != nil {
			t.Errorf("%s must have no path", n)
		}
	}
	for _, n := range []string{"dave", "admin-role", "lambda-admin-role"} {
		if pathOf(r, n) != nil {
			t.Errorf("%s is already admin, not an escalation", n)
		}
	}
	if strings.Join(r.Admins, ",") != "admin-role,lambda-admin-role,dave" {
		t.Errorf("admins: %v", r.Admins)
	}
}

func TestConditionalPathIsFlagged(t *testing.T) {
	p := pathOf(fixture(t), "leo")
	if p == nil || !p.Conditional || !p.Steps[0].Conditional {
		t.Fatalf("%+v", p)
	}
	if pathOf(fixture(t), "alice").Conditional {
		t.Error("alice's path is unconditional")
	}
}

func TestFindings(t *testing.T) {
	r := fixture(t)
	var high, info bool
	for _, f := range r.Findings {
		high = high || (f.Severity == "high" && f.Subject == "public-role")
		info = info || (f.Severity == "info" && f.Subject == "dave")
	}
	if !high || !info {
		t.Errorf("%+v", r.Findings)
	}
}

func TestPathsAreSortedShortestFirst(t *testing.T) {
	r := fixture(t)
	for i := 1; i < len(r.Paths); i++ {
		if len(r.Paths[i-1].Steps) > len(r.Paths[i].Steps) {
			t.Fatal("not sorted by length")
		}
	}
}

const base = `{"UserDetailList":[%s],"RoleDetailList":[%s],"Policies":[]}`

func acct(users, roles string) string {
	return strings.Replace(strings.Replace(base, "%s", users, 1), "%s", roles, 1)
}

const u = `{"UserName":"u","Arn":"arn:aws:iam::1:user/u","UserPolicyList":[{"PolicyName":"p","PolicyDocument":{"Statement":[%s]}}]}`

func TestRootTrustAloneIsNotEnough(t *testing.T) {
	role := `{"RoleName":"r","Arn":"arn:aws:iam::1:role/r","AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:root"},"Action":"sts:AssumeRole"}]},"AttachedManagedPolicies":[{"PolicyArn":"arn:aws:iam::aws:policy/Admin"}]}`
	pol := `"Policies":[{"PolicyName":"Admin","Arn":"arn:aws:iam::aws:policy/Admin","PolicyVersionList":[{"VersionId":"v1","IsDefaultVersion":true,"Document":{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}}]}]`
	nogrant := strings.Replace(acct(strings.Replace(u, "%s", `{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}`, 1), role), `"Policies":[]`, pol, 1)
	if r := load(t, nogrant); len(r.Paths) != 0 {
		t.Errorf("root trust without an AssumeRole grant must not create a path: %+v", r.Paths)
	}
	grant := strings.Replace(acct(strings.Replace(u, "%s", `{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}`, 1), role), `"Policies":[]`, pol, 1)
	if r := load(t, grant); len(r.Paths) != 1 {
		t.Errorf("with the grant there must be a path: %+v", r.Paths)
	}
}

func TestPassRoleNeedsTheServiceToTrustTheRole(t *testing.T) {
	pol := `"Policies":[{"PolicyName":"Admin","Arn":"arn:aws:iam::aws:policy/Admin","PolicyVersionList":[{"VersionId":"v1","IsDefaultVersion":true,"Document":{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}}]}]`
	user := strings.Replace(u, "%s", `{"Effect":"Allow","Action":["iam:PassRole","lambda:CreateFunction","lambda:InvokeFunction"],"Resource":"*"}`, 1)
	mk := func(svc string) string {
		role := `{"RoleName":"r","Arn":"arn:aws:iam::1:role/r","AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Principal":{"Service":"` + svc + `"},"Action":"sts:AssumeRole"}]},"AttachedManagedPolicies":[{"PolicyArn":"arn:aws:iam::aws:policy/Admin"}]}`
		return strings.Replace(acct(user, role), `"Policies":[]`, pol, 1)
	}
	if r := load(t, mk("ec2.amazonaws.com")); len(r.Paths) != 0 {
		t.Error("an EC2-only role cannot be handed to Lambda")
	}
	if r := load(t, mk("lambda.amazonaws.com")); len(r.Paths) != 1 {
		t.Error("a Lambda-trusting admin role can be abused")
	}
}

func TestDenyBlocksAPath(t *testing.T) {
	user := strings.Replace(u, "%s", `{"Effect":"Allow","Action":"iam:PutUserPolicy","Resource":"*"},{"Effect":"Deny","Action":"iam:PutUserPolicy","Resource":"*"}`, 1)
	if r := load(t, acct(user, "")); len(r.Paths) != 0 {
		t.Error("deny must remove the path")
	}
	user = strings.Replace(u, "%s", `{"Effect":"Allow","Action":"iam:PutUserPolicy","Resource":"*"}`, 1)
	if r := load(t, acct(user, "")); len(r.Paths) != 1 {
		t.Error("without the deny there is a path")
	}
}

func TestWildcardIamIsEscalation(t *testing.T) {
	user := strings.Replace(u, "%s", `{"Effect":"Allow","Action":"iam:*","Resource":"*"}`, 1)
	if r := load(t, acct(user, "")); len(r.Paths) != 1 {
		t.Error("iam:* on everything must be reported")
	}
}

func TestCycleInTrustDoesNotHang(t *testing.T) {
	r := func(n, other string) string {
		return `{"RoleName":"` + n + `","Arn":"arn:aws:iam::1:role/` + n + `","AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:role/` + other + `"},"Action":"sts:AssumeRole"}]}}`
	}
	res := load(t, acct("", r("a", "b")+","+r("b", "a")))
	if len(res.Paths) != 0 || len(res.Safe) != 2 {
		t.Errorf("%+v", res)
	}
}
