import type { PrioritizedFinding, AnyFinding } from "@/lib/risk"
import { applyDepBump, deriveSafeVersion } from "./dep-bump"
import { applySecretExtract } from "./secret-extract"

export type FixKind = "dep-bump" | "secret-extract"

export type RunFixInput = {
  finding: PrioritizedFinding | AnyFinding
  fileContent: string
  envExampleContent: string | null
}

export type RunFixResult = {
  kind: FixKind
  patches: { path: string; content: string }[]
  summary: string
}

const JS_TS_EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]

const SIMPLE_ASSIGNMENT =
  /^(\s*)(const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(['"])([^'"]+)\4(\s*;?\s*)$/

function isJsTs(filePath: string): boolean {
  const ext = filePath.slice(filePath.lastIndexOf("."))
  return JS_TS_EXTENSIONS.includes(ext)
}

export function findingSupportsFix(
  finding: PrioritizedFinding | AnyFinding
): FixKind | null {
  if (finding.kind === "dependency") {
    const d = finding.data
    if (d.isTransitive) return null
    if (!d.source) return null
    if (d.source !== "package.json" && d.source !== "requirements.txt") return null
    if (!deriveSafeVersion(d.vulnerable_versions)) return null
    return "dep-bump"
  }

  if (finding.kind === "secret") {
    const d = finding.data
    if (d.likelyTestFixture) return null
    if (d.source === "history") return null
    if (!isJsTs(d.filePath)) return null
    if (!SIMPLE_ASSIGNMENT.test(d.lineContent)) return null
    return "secret-extract"
  }

  if (finding.kind === "code") {
    const d = finding.data
    if (d.likelyTestFixture) return null
    if (d.category !== "hardcoded-creds") return null
    if (!isJsTs(d.filePath)) return null
    if (!SIMPLE_ASSIGNMENT.test(d.lineContent)) return null
    return "secret-extract"
  }

  return null
}

export function runFixEngine(input: RunFixInput): RunFixResult {
  const kind = findingSupportsFix(input.finding)
  if (!kind) {
    throw new Error(`Finding type unsupported for auto-fix: kind=${input.finding.kind}`)
  }

  if (kind === "dep-bump") {
    if (input.finding.kind !== "dependency") {
      throw new Error("dep-bump expects a dependency finding")
    }
    const result = applyDepBump({
      finding: input.finding.data,
      manifestContent: input.fileContent,
      manifestPath: input.finding.data.source!,
    })
    return {
      kind,
      patches: result.patches,
      summary: `Bump ${input.finding.data.package} to ${result.newVersion}`,
    }
  }

  if (input.finding.kind !== "secret" && input.finding.kind !== "code") {
    throw new Error("secret-extract expects a secret or code finding")
  }

  const result = applySecretExtract({
    finding: input.finding.data,
    fileContent: input.fileContent,
    envExampleContent: input.envExampleContent,
  })
  return {
    kind,
    patches: result.patches,
    summary: `Extract hardcoded secret into process.env.${result.envVarName}`,
  }
}

export { deriveSafeVersion, applyDepBump, applySecretExtract }
