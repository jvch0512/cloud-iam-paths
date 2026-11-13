# IAM privilege escalation report

Account `111122223333`. **9 of 15 principals** can reach administrator access.

| Principal | Kind | Steps | Route |
|---|---|---|---|
| alice | user | 1 | ADMIN (CreatePolicyVersion) |
| bob | user | 1 | lambda-admin-role (PassRole+lambda) |
| build-role | role | 1 | ADMIN (AttachRolePolicy) |
| carol | user | 1 | ADMIN (AddUserToGroup) |
| erin | user | 1 | dave (CreateAccessKey) |
| ivan | user | 1 | admin-role (UpdateAssumeRolePolicy) |
| kim | user | 1 | ADMIN (SetDefaultPolicyVersion) |
| leo | user | 1 | ADMIN (AttachUserPolicy) |
| frank | user | 2 | build-role (AssumeRole) -> ADMIN (AttachRolePolicy) |

## Details

### alice

1. **CreatePolicyVersion**: Publish a new default version of the attached policy DevPolicy that allows everything.
   - needs: `iam:CreatePolicyVersion on arn:aws:iam::111122223333:policy/DevPolicy`

### bob

1. **PassRole+lambda**: Pass lambda-admin-role to lambda and create and invoke a Lambda function that runs as the role.
   - needs: `iam:PassRole on arn:aws:iam::111122223333:role/lambda-admin-role`, `lambda:CreateFunction`, `lambda:InvokeFunction`

### build-role

1. **AttachRolePolicy**: Attach or write an administrator policy on this role itself.
   - needs: `iam:AttachRolePolicy on arn:aws:iam::111122223333:role/build-role`

### carol

1. **AddUserToGroup**: Add themselves to the administrator group ops-admins.
   - needs: `iam:AddUserToGroup on arn:aws:iam::111122223333:group/ops-admins`

### erin

1. **CreateAccessKey**: Create credentials for dave and sign in as them.
   - needs: `iam:CreateAccessKey on arn:aws:iam::111122223333:user/dave`

### ivan

1. **UpdateAssumeRolePolicy**: Rewrite the trust policy of admin-role to trust them, then assume it.
   - needs: `iam:UpdateAssumeRolePolicy on arn:aws:iam::111122223333:role/admin-role`

### kim

1. **SetDefaultPolicyVersion**: Switch LegacyPolicy back to its older version v1, which allows everything.
   - needs: `iam:SetDefaultPolicyVersion on arn:aws:iam::111122223333:policy/LegacyPolicy`

### leo

1. **AttachUserPolicy**: Attach or write an administrator policy on their own user.
   - needs: `iam:AttachUserPolicy on arn:aws:iam::111122223333:user/leo`

### frank

1. **AssumeRole**: Assume the role build-role, whose trust policy allows them.
   - needs: `sts:AssumeRole on arn:aws:iam::111122223333:role/build-role`
2. **AttachRolePolicy**: Attach or write an administrator policy on this role itself.
   - needs: `iam:AttachRolePolicy on arn:aws:iam::111122223333:role/build-role`

No path found for: public-role, grace, heidi.

## Findings

- **high** `public-role`: Trust policy allows any principal ("*") to assume this role with no condition.
- **info** `dave`: User has administrator access directly; prefer a role that is assumed with MFA.

This analysis reads identity and trust policies only. Service control policies, permission boundaries, session policies, resource policies and most conditions are not evaluated, so treat results as candidates to verify.
