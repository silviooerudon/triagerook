import { describe, it, expect } from "vitest"
import { scanCloudFormation, looksLikeCloudFormation } from "@/lib/iac-cloudformation"

const ids = (content: string, path = "template.yaml") =>
  scanCloudFormation(content, path).map((f) => f.ruleId)

describe("looksLikeCloudFormation", () => {
  it("recognizes templates by format version or Resources + AWS::", () => {
    expect(looksLikeCloudFormation("AWSTemplateFormatVersion: '2010-09-09'")).toBe(true)
    expect(
      looksLikeCloudFormation("Resources:\n  Bucket:\n    Type: AWS::S3::Bucket"),
    ).toBe(true)
    expect(looksLikeCloudFormation('"Resources": { "B": { "Type": "AWS::S3::Bucket" } }')).toBe(true)
  })

  it("rejects unrelated YAML/JSON", () => {
    expect(looksLikeCloudFormation("name: build\non: push\njobs: {}")).toBe(false)
    expect(looksLikeCloudFormation('{"name": "my-pkg", "version": "1.0.0"}')).toBe(false)
  })
})

describe("scanCloudFormation — YAML", () => {
  const base = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n"

  it("flags a public S3 ACL", () => {
    expect(ids(base + "  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead")).toContain(
      "cfn-s3-public-acl",
    )
  })

  it("flags wildcard IAM action and resource", () => {
    const tmpl = base + "  P:\n    Type: AWS::IAM::Policy\n    Properties:\n      PolicyDocument:\n        Statement:\n          - Effect: Allow\n            Action: '*'\n            Resource: '*'"
    const got = ids(tmpl)
    expect(got).toContain("cfn-iam-wildcard-action")
    expect(got).toContain("cfn-iam-wildcard-resource")
  })

  it("flags a publicly accessible RDS instance and disabled encryption", () => {
    const tmpl = base + "  DB:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      PubliclyAccessible: true\n      StorageEncrypted: false"
    const got = ids(tmpl)
    expect(got).toContain("cfn-rds-publicly-accessible")
    expect(got).toContain("cfn-unencrypted-storage")
  })

  it("flags an ingress 0.0.0.0/0 but NOT egress 0.0.0.0/0", () => {
    const tmpl = base +
      "  SG:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n" +
      "      SecurityGroupIngress:\n        - CidrIp: 0.0.0.0/0\n" +
      "      SecurityGroupEgress:\n        - CidrIp: 0.0.0.0/0"
    const findings = scanCloudFormation(tmpl, "template.yaml").filter(
      (f) => f.ruleId === "cfn-security-group-world-ingress",
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].lineNumber).toBe(7) // the ingress CidrIp line
  })

  it("flags a disabled public access block flag", () => {
    expect(ids(base + "  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      PublicAccessBlockConfiguration:\n        BlockPublicAcls: false")).toContain(
      "cfn-s3-public-access-block-disabled",
    )
  })
})

describe("scanCloudFormation — JSON", () => {
  it("flags wildcard action in a JSON template", () => {
    const tmpl = `{
      "AWSTemplateFormatVersion": "2010-09-09",
      "Resources": {
        "P": { "Type": "AWS::IAM::Role", "Properties": {
          "Policies": [{ "PolicyDocument": { "Statement": [
            { "Effect": "Allow", "Action": "*", "Resource": "*" }
          ]}}]
        }}
      }
    }`
    const got = scanCloudFormation(tmpl, "template.json").map((f) => f.ruleId)
    expect(got).toContain("cfn-iam-wildcard-action")
    expect(got).toContain("cfn-iam-wildcard-resource")
  })
})

describe("scanCloudFormation — hygiene", () => {
  it("returns [] for non-template content", () => {
    expect(scanCloudFormation("name: ci\non: push", "x.yaml")).toEqual([])
    expect(scanCloudFormation('{"scripts": {"build": "tsc"}}', "package.json")).toEqual([])
  })
})
