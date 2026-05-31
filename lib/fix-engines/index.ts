import type { PrioritizedFinding, AnyFinding } from "@/lib/risk"
import { applyDepBump, deriveSafeVersion } from "./dep-bump"
import { applySecretExtract } from "./secret-extract"
import {
  applyDockerfileBaseImageBump,
  dockerfileBumpSupported,
} from "./dockerfile-baseimage"
import { applyGhaPermissionsFix } from "./gha-permissions"

export type FixKind =
  | "dep-bump"
  | "secret-extract"
  | "dockerfile-baseimage-bump"
  | "gha-permissions-fix"

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
const PY_EXTENSIONS = [".py"]

const JS_ASSIGNMENT =
  /^(\s*)(const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(['"])([^'"]+)\4(\s*;?\s*)$/
const PY_ASSIGNMENT =
  /^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['"])([^'"]+)\3(\s*)$/

function isExtractable(filePath: string, lineContent: string): boolean {
  const ext = filePath.slice(filePath.lastIndexOf("."))
  if (JS_TS_EXTENSIONS.includes(ext)) return JS_ASSIGNMENT.test(lineContent)
  if (PY_EXTENSIONS.includes(ext)) return PY_ASSIGNMENT.test(lineContent)
  return false
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
    if (!isExtractable(d.filePath, d.lineContent)) return null
    return "secret-extract"
  }

  if (finding.kind === "code") {
    const d = finding.data
    if (d.likelyTestFixture) return null
    if (d.category !== "hardcoded-creds") return null
    if (!isExtractable(d.filePath, d.lineContent)) return null
    return "secret-extract"
  }

  if (finding.kind === "iac") {
    const d = finding.data
    if (d.likelyTestFixture) return null
    if (d.ruleId === "dockerfile-base-image-eol") {
      return dockerfileBumpSupported(d.lineContent) ? "dockerfile-baseimage-bump" : null
    }
    if (d.ruleId === "gha-permissions-write-all") return "gha-permissions-fix"
    return null
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

  if (kind === "dockerfile-baseimage-bump") {
    if (input.finding.kind !== "iac") {
      throw new Error("dockerfile-baseimage-bump expects an iac finding")
    }
    const result = applyDockerfileBaseImageBump({
      finding: input.finding.data,
      fileContent: input.fileContent,
    })
    return {
      kind,
      patches: result.patches,
      summary: `Bump end-of-life base image to ${result.newRef}`,
    }
  }

  if (kind === "gha-permissions-fix") {
    if (input.finding.kind !== "iac") {
      throw new Error("gha-permissions-fix expects an iac finding")
    }
    const result = applyGhaPermissionsFix({
      finding: input.finding.data,
      fileContent: input.fileContent,
    })
    return {
      kind,
      patches: result.patches,
      summary: "Replace permissions: write-all with least-privilege contents: read",
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
  const filePath = input.finding.data.filePath
  const isPython = filePath.endsWith(".py")
  const reference = isPython
    ? `os.environ['${result.envVarName}']`
    : `process.env.${result.envVarName}`
  return {
    kind,
    patches: result.patches,
    summary: `Extract hardcoded secret into ${reference}`,
  }
}

export {
  deriveSafeVersion,
  applyDepBump,
  applySecretExtract,
  applyDockerfileBaseImageBump,
  applyGhaPermissionsFix,
}
