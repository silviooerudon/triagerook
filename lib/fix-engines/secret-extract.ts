import type { CodeFinding, SecretFinding } from "@/lib/types"

export type SecretExtractInput = {
  finding: SecretFinding | CodeFinding
  fileContent: string
  envExampleContent: string | null
}

export type SecretExtractResult = {
  patches: { path: string; content: string }[]
  envVarName: string
}

const JS_EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]
const PY_EXTENSIONS = [".py"]

const JS_ASSIGNMENT =
  /^(\s*)(const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(['"])([^'"]+)\4(\s*;?\s*)$/

// Python: no leading keyword, identifier = string literal. Allows both
// `snake_case = "..."` and `SCREAMING = "..."` (modules constants by
// convention). Capture groups: indent / identifier / quote / literal /
// trailing whitespace.
const PY_ASSIGNMENT =
  /^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['"])([^'"]+)\3(\s*)$/

export function deriveEnvVarName(identifier: string): string {
  return identifier
    .replace(/[-]/g, "_")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toUpperCase()
}

export function applySecretExtract(input: SecretExtractInput): SecretExtractResult {
  const { finding, fileContent, envExampleContent } = input
  const filePath = finding.filePath
  const ext = filePath.slice(filePath.lastIndexOf("."))

  if (JS_EXTENSIONS.includes(ext)) {
    return applyJsTsExtract({ finding, fileContent, envExampleContent, filePath })
  }
  if (PY_EXTENSIONS.includes(ext)) {
    return applyPythonExtract({ finding, fileContent, envExampleContent, filePath })
  }
  throw new Error(`Unsupported file extension '${ext}' (only JS/TS family and Python in v1)`)
}

type ExtractContext = SecretExtractInput & { filePath: string }

function applyJsTsExtract(ctx: ExtractContext): SecretExtractResult {
  const lineMatch = JS_ASSIGNMENT.exec(ctx.finding.lineContent)
  if (!lineMatch) {
    throw new Error(
      `Line shape unsupported: only simple 'const|let|var <ident> = "<literal>"' assignments are extractable in v1`,
    )
  }

  const [, indent, decl, identifier, , , trailing] = lineMatch
  const envVarName = deriveEnvVarName(identifier)
  const replacementLine = `${indent}${decl} ${identifier} = process.env.${envVarName}${trailing}`

  return finalize(ctx, envVarName, replacementLine)
}

function applyPythonExtract(ctx: ExtractContext): SecretExtractResult {
  const lineMatch = PY_ASSIGNMENT.exec(ctx.finding.lineContent)
  if (!lineMatch) {
    throw new Error(
      `Line shape unsupported: only simple '<ident> = "<literal>"' assignments are extractable in v1`,
    )
  }

  const [, indent, identifier, , , trailing] = lineMatch
  const envVarName = deriveEnvVarName(identifier)
  const replacementLine = `${indent}${identifier} = os.environ['${envVarName}']${trailing}`

  let result = finalize(ctx, envVarName, replacementLine)

  // Python needs `os` imported to call os.environ[]. Prepend `import os` to
  // the patched file if neither `import os` nor `from os import environ`
  // is already present. Idempotent: never adds a duplicate.
  const codePatch = result.patches.find((p) => p.path === ctx.filePath)
  if (codePatch && !hasOsImport(codePatch.content)) {
    codePatch.content = `import os\n${codePatch.content}`
  }
  return result
}

function finalize(
  ctx: ExtractContext,
  envVarName: string,
  replacementLine: string,
): SecretExtractResult {
  const lines = ctx.fileContent.split("\n")
  const idx = ctx.finding.lineNumber - 1
  if (idx < 0 || idx >= lines.length) {
    throw new Error(
      `Finding lineNumber ${ctx.finding.lineNumber} out of bounds for ${ctx.filePath} (${lines.length} lines)`,
    )
  }
  lines[idx] = replacementLine

  const patches: { path: string; content: string }[] = [
    { path: ctx.filePath, content: lines.join("\n") },
  ]

  const envPatch = buildEnvExamplePatch(envVarName, ctx.finding, ctx.envExampleContent)
  if (envPatch) patches.push(envPatch)

  return { patches, envVarName }
}

function hasOsImport(content: string): boolean {
  return (
    /^import os\b/m.test(content) ||
    /^from os import\b/m.test(content)
  )
}

function buildEnvExamplePatch(
  envVarName: string,
  finding: SecretFinding | CodeFinding,
  existing: string | null,
): { path: string; content: string } | null {
  const declarationLineRe = new RegExp(`^${envVarName}=`, "m")
  if (existing && declarationLineRe.test(existing)) {
    return null
  }

  const description = "patternName" in finding ? finding.patternName : finding.ruleName
  const comment = `# ${description}`
  const newEntry = `${comment}\n${envVarName}=\n`

  const base = existing ?? ""
  const separator = !base || base.endsWith("\n") ? "" : "\n"
  return { path: ".env.example", content: `${base}${separator}${newEntry}` }
}
