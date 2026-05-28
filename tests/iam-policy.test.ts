import { describe, it, expect } from "vitest"
import { scanIamPolicy, IAM_POLICY_RULES } from "@/lib/iam-policy"

const POLICY = (statement: string) =>
  `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      ${statement}
    }
  ]
}`

describe("scanIamPolicy — AWS policy documents", () => {
  it("flags a wildcard action", () => {
    const ids = scanIamPolicy(POLICY(`"Action": "*", "Resource": "arn:aws:s3:::b/*"`), "policy.json").map(
      (f) => f.ruleId,
    )
    expect(ids).toContain("iam-aws-wildcard-action")
  })

  it("flags a service-wide wildcard as the medium rule, not the high one", () => {
    const ids = scanIamPolicy(POLICY(`"Action": "s3:*", "Resource": "arn:aws:s3:::b"`), "policy.json").map(
      (f) => f.ruleId,
    )
    expect(ids).toContain("iam-aws-service-wildcard-action")
    expect(ids).not.toContain("iam-aws-wildcard-action")
  })

  it("flags a wildcard resource", () => {
    const ids = scanIamPolicy(POLICY(`"Action": "s3:GetObject", "Resource": "*"`), "policy.json").map(
      (f) => f.ruleId,
    )
    expect(ids).toContain("iam-aws-wildcard-resource")
  })

  it("flags a public principal (string and AWS-object forms)", () => {
    const a = scanIamPolicy(POLICY(`"Principal": "*", "Action": "sts:AssumeRole"`), "trust.json").map(
      (f) => f.ruleId,
    )
    const b = scanIamPolicy(
      POLICY(`"Principal": { "AWS": "*" }, "Action": "sts:AssumeRole"`),
      "trust.json",
    ).map((f) => f.ruleId)
    expect(a).toContain("iam-aws-public-principal")
    expect(b).toContain("iam-aws-public-principal")
  })

  it("does NOT flag a scoped policy", () => {
    const findings = scanIamPolicy(
      POLICY(`"Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"`),
      "policy.json",
    )
    expect(findings).toHaveLength(0)
  })

  it("requires policy-doc context: a lone Action:* in arbitrary JSON is ignored", () => {
    const json = `{ "Action": "*", "note": "not a policy" }`
    expect(scanIamPolicy(json, "config.json")).toHaveLength(0)
  })
})

describe("scanIamPolicy — GCP primitive roles", () => {
  it("flags roles/owner anywhere", () => {
    const yaml = `bindings:\n  - role: roles/owner\n    members: ["user:a@b.com"]`
    expect(scanIamPolicy(yaml, "bindings.yaml").some((f) => f.ruleId === "iam-gcp-primitive-owner")).toBe(true)
  })

  it("flags roles/editor", () => {
    expect(
      scanIamPolicy(`role = "roles/editor"`, "iam.yaml").some((f) => f.ruleId === "iam-gcp-primitive-editor"),
    ).toBe(true)
  })

  it("does not flag a predefined role", () => {
    expect(scanIamPolicy(`role: roles/storage.objectViewer`, "iam.yaml")).toHaveLength(0)
  })
})

describe("scanIamPolicy — scope", () => {
  it("skips .tf and .tfvars (owned by the Terraform scanner)", () => {
    expect(scanIamPolicy(POLICY(`"Action": "*"`), "main.tf")).toHaveLength(0)
    expect(scanIamPolicy(`role = "roles/owner"`, "vars.tfvars")).toHaveLength(0)
  })

  it("emits well-formed IaCFinding objects with iam-policy category", () => {
    const [f] = scanIamPolicy(POLICY(`"Action": "*"`), "p.json")
    expect(f.category).toBe("iam-policy")
    expect(f.filePath).toBe("p.json")
    expect(f.lineNumber).toBeGreaterThan(0)
    expect(f.remediation.length).toBeGreaterThan(0)
  })

  it("every rule has a non-empty remediation and iam- id", () => {
    for (const r of IAM_POLICY_RULES) {
      expect(r.remediation.trim().length).toBeGreaterThan(0)
      expect(r.id.startsWith("iam-")).toBe(true)
    }
  })
})
