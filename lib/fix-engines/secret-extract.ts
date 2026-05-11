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

const SUPPORTED_EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]

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
  if (!SUPPORTED_EXTENSIONS.includes(ext)) {
    throw new Error(`Unsupported file extension '${ext}' (only JS/TS family in v1)`)
  }

  const lineMatch = /^(\s*)(const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(['"])([^'"]+)\4(\s*;?\s*)$/.exec(
    finding.lineContent
  )

  if (!lineMatch) {
    throw new Error(
      `Line shape unsupported: only simple 'const|let|var <ident> = "<literal>"' assignments are extractable in v1`
    )
  }

  const [, indent, decl, identifier, , , trailing] = lineMatch
  const envVarName = deriveEnvVarName(identifier)
  const replacementLine = `${indent}${decl} ${identifier} = process.env.${envVarName}${trailing}`

  const lines = fileContent.split("\n")
  const idx = finding.lineNumber - 1
  if (idx < 0 || idx >= lines.length) {
    throw new Error(
      `Finding lineNumber ${finding.lineNumber} out of bounds for ${filePath} (${lines.length} lines)`
    )
  }

  lines[idx] = replacementLine

  const patches: { path: string; content: string }[] = [
    { path: filePath, content: lines.join("\n") },
  ]

  const envPatch = buildEnvExamplePatch(envVarName, finding, envExampleContent)
  if (envPatch) patches.push(envPatch)

  return { patches, envVarName }
}

function buildEnvExamplePatch(
  envVarName: string,
  finding: SecretFinding | CodeFinding,
  existing: string | null
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
