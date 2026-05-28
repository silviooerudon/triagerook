import { describe, it, expect } from "vitest"
import {
  isTerraformPath,
  scanTerraform,
  TERRAFORM_RULES,
} from "@/lib/iac-terraform"

describe("isTerraformPath", () => {
  it("matches .tf and .tfvars files", () => {
    expect(isTerraformPath("main.tf")).toBe(true)
    expect(isTerraformPath("infra/modules/vpc/main.tf")).toBe(true)
    expect(isTerraformPath("prod.tfvars")).toBe(true)
  })

  it("rejects non-Terraform paths", () => {
    expect(isTerraformPath("main.tfstate")).toBe(false)
    expect(isTerraformPath("README.md")).toBe(false)
    expect(isTerraformPath("config.yaml")).toBe(false)
  })
})

describe("scanTerraform — S3", () => {
  it("flags a public-read ACL", () => {
    const tf = `resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}`
    const findings = scanTerraform(tf, "main.tf")
    expect(findings.some((f) => f.ruleId === "tf-s3-public-acl")).toBe(true)
  })

  it("does not flag a private ACL", () => {
    const tf = `resource "aws_s3_bucket" "b" {\n  acl = "private"\n}`
    expect(scanTerraform(tf, "main.tf")).toHaveLength(0)
  })

  it("flags a disabled public access block", () => {
    const tf = `resource "aws_s3_bucket_public_access_block" "b" {\n  block_public_acls = false\n  restrict_public_buckets = false\n}`
    const ids = scanTerraform(tf, "main.tf").map((f) => f.ruleId)
    expect(ids.filter((id) => id === "tf-s3-public-access-block-disabled")).toHaveLength(2)
  })
})

describe("scanTerraform — IAM wildcards", () => {
  it("flags wildcard Action and Resource in a JSON-style policy", () => {
    const tf = `data "aws_iam_policy_document" "p" {\n  statement {\n    actions   = ["*"]\n    resources = ["*"]\n  }\n}`
    const ids = scanTerraform(tf, "iam.tf").map((f) => f.ruleId)
    expect(ids).toContain("tf-iam-wildcard-action")
    expect(ids).toContain("tf-iam-wildcard-resource")
  })

  it("flags wildcard in heredoc JSON policy", () => {
    const tf = `  "Action": "*",\n  "Resource": "*"`
    const ids = scanTerraform(tf, "iam.tf").map((f) => f.ruleId)
    expect(ids).toContain("tf-iam-wildcard-action")
    expect(ids).toContain("tf-iam-wildcard-resource")
  })

  it("does not flag a scoped action list", () => {
    const tf = `    actions = ["s3:GetObject", "s3:PutObject"]`
    expect(scanTerraform(tf, "iam.tf")).toHaveLength(0)
  })
})

describe("scanTerraform — encryption & exposure", () => {
  it("flags unencrypted storage", () => {
    const tf = `resource "aws_db_instance" "d" {\n  storage_encrypted = false\n}`
    expect(scanTerraform(tf, "rds.tf").some((f) => f.ruleId === "tf-unencrypted-storage")).toBe(true)
  })

  it("flags a publicly accessible database", () => {
    const tf = `resource "aws_db_instance" "d" {\n  publicly_accessible = true\n}`
    expect(
      scanTerraform(tf, "rds.tf").some((f) => f.ruleId === "tf-rds-publicly-accessible"),
    ).toBe(true)
  })
})

describe("scanTerraform — security group ingress", () => {
  it("flags 0.0.0.0/0 ingress", () => {
    const tf = `resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`
    expect(
      scanTerraform(tf, "sg.tf").some((f) => f.ruleId === "tf-security-group-world-ingress"),
    ).toBe(true)
  })

  it("flags IPv6 ::/0 ingress", () => {
    const tf = `resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = ["::/0"]
  }
}`
    expect(
      scanTerraform(tf, "sg.tf").some((f) => f.ruleId === "tf-security-group-world-ingress"),
    ).toBe(true)
  })

  it("does NOT flag open egress (egress to the world is normal)", () => {
    const tf = `resource "aws_security_group" "sg" {
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`
    expect(
      scanTerraform(tf, "sg.tf").some((f) => f.ruleId === "tf-security-group-world-ingress"),
    ).toBe(false)
  })

  it("does not flag a restricted ingress CIDR", () => {
    const tf = `resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
  }
}`
    expect(
      scanTerraform(tf, "sg.tf").some((f) => f.ruleId === "tf-security-group-world-ingress"),
    ).toBe(false)
  })
})

describe("scanTerraform — finding shape", () => {
  it("emits well-formed IaCFinding objects", () => {
    const tf = `  acl = "public-read"`
    const [f] = scanTerraform(tf, "main.tf")
    expect(f.category).toBe("terraform")
    expect(f.filePath).toBe("main.tf")
    expect(f.lineNumber).toBe(1)
    expect(f.remediation.length).toBeGreaterThan(0)
    expect(typeof f.description).toBe("string")
  })

  it("every rule carries a non-empty remediation", () => {
    for (const rule of TERRAFORM_RULES) {
      expect(rule.remediation.trim().length).toBeGreaterThan(0)
      expect(rule.id.startsWith("tf-")).toBe(true)
    }
  })
})
