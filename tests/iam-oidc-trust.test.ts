import { describe, it, expect } from "vitest"
import { __testExtractStatements, __testDetectOidcWeaknesses } from "@/lib/iam"

// OIDC trust weakness detection lives in lib/iam.ts (assessIAM path), distinct
// from scanIamPolicy in lib/iam-policy.ts. We drive the real path:
// raw JSON -> extractStatements -> detectOidcWeaknesses.

// A GitHub OIDC trust policy with a given StringLike `sub` constraint. The
// Federated principal must mention the GitHub OIDC host for the statement to be
// recognized as an OIDC trust.
const TRUST = (sub: string) => `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "${sub}"
        }
      }
    }
  ]
}`

// No Condition block at all — global trust.
const TRUST_NO_CONDITION = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity"
    }
  ]
}`

function findingsFor(content: string) {
  const stmts = __testExtractStatements(content, "aws-oidc-trust-policy.json")
  return stmts.flatMap((s) => __testDetectOidcWeaknesses(s, "aws-oidc-trust-policy.json"))
}

describe("detectOidcWeaknesses — wildcard repo in sub claim", () => {
  it("flags the canonical org-wide wildcard `repo:org/*` (was a false negative)", () => {
    const findings = findingsFor(TRUST("repo:silviooerudon/*"))
    expect(findings).toHaveLength(1)
    expect(findings[0].ruleId).toBe("iam-oidc-wildcard-repo")
    expect(findings[0].severity).toBe("critical")
  })

  it("flags a bare `repo:*` (any org, any repo)", () => {
    const findings = findingsFor(TRUST("repo:*"))
    expect(findings.map((f) => f.ruleId)).toContain("iam-oidc-wildcard-repo")
    expect(findings[0].severity).toBe("critical")
  })

  it("still flags `repo:org/*:ref:...` (regression — already matched before fix)", () => {
    const findings = findingsFor(TRUST("repo:silviooerudon/*:ref:refs/heads/main"))
    expect(findings.map((f) => f.ruleId)).toContain("iam-oidc-wildcard-repo")
    expect(findings[0].severity).toBe("critical")
  })
})

describe("detectOidcWeaknesses — regression guards for other shapes", () => {
  it("flags wildcard ref `repo:org/repo:*` as the high-severity ref rule, not wildcard-repo", () => {
    const findings = findingsFor(TRUST("repo:silviooerudon/triagerook:*"))
    const ids = findings.map((f) => f.ruleId)
    expect(ids).toContain("iam-oidc-wildcard-ref")
    expect(ids).not.toContain("iam-oidc-wildcard-repo")
    expect(findings[0].severity).toBe("high")
  })

  it("flags a pull_request trust", () => {
    const findings = findingsFor(TRUST("repo:silviooerudon/triagerook:pull_request"))
    expect(findings.map((f) => f.ruleId)).toContain("iam-oidc-pull-request-trust")
  })

  it("flags a trust with no Condition block at all", () => {
    const findings = findingsFor(TRUST_NO_CONDITION)
    expect(findings.map((f) => f.ruleId)).toContain("iam-oidc-no-condition")
  })

  it("does NOT flag a properly pinned sub (repo + ref both specific)", () => {
    const findings = findingsFor(TRUST("repo:silviooerudon/triagerook:ref:refs/heads/main"))
    expect(findings).toHaveLength(0)
  })
})
