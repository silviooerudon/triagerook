import { describe, it, expect } from "vitest"
import { scanIamPolicy } from "@/lib/iam-policy"

const ids = (content: string, path = "main.bicep") =>
  scanIamPolicy(content, path).map((f) => f.ruleId)

describe("scanIamPolicy — Azure RBAC", () => {
  it("flags the Owner role GUID anywhere (authoritative)", () => {
    expect(ids("roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions','8e3af657-a8ff-443c-a75c-2fe8c4bcb635')")).toContain(
      "iam-azure-rbac-owner",
    )
  })

  it("flags the Contributor role GUID", () => {
    expect(ids("roleDefinitionId: '/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c'")).toContain(
      "iam-azure-rbac-contributor",
    )
  })

  it("flags Owner/Contributor by name only inside an Azure context", () => {
    const az = "az role assignment create --assignee x --role Owner --scope /subscriptions/abc"
    expect(ids(az, "deploy.sh")).toContain("iam-azure-rbac-owner")

    const cli = 'az role assignment create --role "Contributor" --scope /subscriptions/abc'
    expect(ids(cli, "deploy.sh")).toContain("iam-azure-rbac-contributor")
  })

  it("does NOT flag the word Owner outside an Azure context", () => {
    expect(ids('const role = "Owner"', "app.ts")).not.toContain("iam-azure-rbac-owner")
  })

  it("flags a custom role with wildcard Actions in Azure context", () => {
    const def = 'roleDefinition: { "Actions": ["*"], "AssignableScopes": ["/subscriptions/x"] }'
    expect(ids(def)).toContain("iam-azure-custom-role-wildcard")
  })
})

describe("scanIamPolicy — GitHub OAuth/PAT scopes", () => {
  it("flags an over-broad scope request", () => {
    expect(ids('scope: "repo,delete_repo,admin:org"', "auth.ts")).toContain(
      "iam-github-broad-oauth-scope",
    )
    expect(ids("scopes = ['admin:enterprise', 'read:org']", "config.py")).toContain(
      "iam-github-broad-oauth-scope",
    )
  })

  it("flags the CLI --scope(s) flag form (space-separated)", () => {
    expect(ids('gh auth login --scopes "admin:org,repo"', "setup.sh")).toContain(
      "iam-github-broad-oauth-scope",
    )
    expect(ids("gh auth refresh --scope delete_repo", "ci.sh")).toContain(
      "iam-github-broad-oauth-scope",
    )
  })

  it("does NOT flag benign scopes", () => {
    expect(ids('scope: "read:org repo:status"', "auth.ts")).not.toContain(
      "iam-github-broad-oauth-scope",
    )
    expect(ids("gh auth login --scopes read:org", "setup.sh")).not.toContain(
      "iam-github-broad-oauth-scope",
    )
  })

  it("does NOT flag prose merely mentioning a scope name", () => {
    expect(ids("// the delete_repo scope is dangerous; never request it", "notes.ts")).not.toContain(
      "iam-github-broad-oauth-scope",
    )
  })
})
