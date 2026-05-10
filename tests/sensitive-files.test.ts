import { describe, it, expect } from "vitest"
import { findSensitiveFiles } from "@/lib/sensitive-files"

describe("findSensitiveFiles", () => {
  it("flags id_rsa as ssh-key", () => {
    const findings = findSensitiveFiles(["id_rsa"])
    expect(findings).toHaveLength(1)
    expect(findings[0].kind).toBe("ssh-key")
    expect(findings[0].severity).toBe("critical")
  })

  it("flags terraform.tfstate as terraform-state", () => {
    const findings = findSensitiveFiles(["infra/terraform.tfstate"])
    expect(findings).toHaveLength(1)
    expect(findings[0].kind).toBe("terraform-state")
  })

  it("flags .env.production as env-production", () => {
    const findings = findSensitiveFiles([".env.production"])
    expect(findings).toHaveLength(1)
    expect(findings[0].kind).toBe("env-production")
  })

  it("flags generic .env but not .env.example", () => {
    const findings = findSensitiveFiles([".env", ".env.example", ".env.sample"])
    const kinds = findings.map((f) => f.kind)
    expect(kinds).toContain("env-generic")
    expect(findings.map((f) => f.filePath)).toEqual([".env"])
  })

  it("flags .pem and .key files but skips public cert variants", () => {
    const findings = findSensitiveFiles([
      "private.key",
      "server.pem",
      "public.pem",
      "server.crt.pem",
    ])
    const paths = findings.map((f) => f.filePath)
    expect(paths).toContain("private.key")
    expect(paths).toContain("server.pem")
    expect(paths).not.toContain("public.pem")
    expect(paths).not.toContain("server.crt.pem")
  })

  it("flags AWS credentials file", () => {
    const findings = findSensitiveFiles([".aws/credentials"])
    expect(findings[0].kind).toBe("aws-credentials")
  })

  it("flags kubeconfig", () => {
    const findings = findSensitiveFiles([".kube/config", "kubeconfig.yaml"])
    expect(findings.map((f) => f.kind)).toEqual(["kubeconfig", "kubeconfig"])
  })

  it("flags .npmrc", () => {
    expect(findSensitiveFiles([".npmrc"])[0].kind).toBe("npmrc-auth")
  })

  it("skips files inside node_modules / .git / vendor / build", () => {
    const findings = findSensitiveFiles([
      "node_modules/foo/id_rsa",
      ".git/config",
      "vendor/lib/.env.production",
      "build/output/.env",
      "dist/.env",
    ])
    expect(findings).toEqual([])
  })

  it("does NOT flag schema migration SQL as a database dump", () => {
    const findings = findSensitiveFiles([
      "supabase/migrations/20250101_init.sql",
      "prisma/migrations/20250101000000_init/migration.sql",
      "db/migrate/001_create_users.sql",
    ])
    expect(findings).toEqual([])
  })

  it("does flag a real-looking SQL dump", () => {
    const findings = findSensitiveFiles(["backup/db_dump.sql"])
    expect(findings.some((f) => f.kind === "database-dump")).toBe(true)
  })

  it("returns empty array for empty input", () => {
    expect(findSensitiveFiles([])).toEqual([])
  })
})
