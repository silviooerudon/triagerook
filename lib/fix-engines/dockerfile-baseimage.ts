import type { IaCFinding } from "@/lib/types"

// Auto-fix engine for the `dockerfile-base-image-eol` finding: bump an
// end-of-life base image to a currently-supported release, preserving the
// variant suffix (-alpine, -slim, …) and any registry prefix.
//
// Pure text transform — no network. Only numeric-leading tags on images in the
// curated map are supported; codename tags (stretch, bionic) and discontinued
// distros (centos) return unsupported so we never propose a risky distro
// switch automatically.

const CURRENT_TAG: Record<string, string> = {
  node: "22",
  python: "3.12",
  ruby: "3.3",
  php: "8.3",
  golang: "1.22",
  debian: "12",
  ubuntu: "24.04",
  alpine: "3.20",
}

type ParsedFrom = { imagePart: string; tag: string; shortName: string }

function parseFrom(line: string): ParsedFrom | null {
  const m = line.match(/^\s*FROM\s+(.+?)\s*$/i)
  if (!m) return null
  let rest = m[1]
    .replace(/^--platform=\S+\s+/i, "")
    .replace(/\s+AS\s+\S+\s*$/i, "")
    .trim()
  rest = rest.split("@")[0] // drop digest
  const lastColon = rest.lastIndexOf(":")
  const lastSlash = rest.lastIndexOf("/")
  if (lastColon <= lastSlash) return null // no tag (registry port has a slash after it)
  const imagePart = rest.slice(0, lastColon)
  const tag = rest.slice(lastColon + 1)
  const shortName = imagePart.split("/").pop()!.toLowerCase()
  return { imagePart, tag, shortName }
}

function bumpable(p: ParsedFrom | null): p is ParsedFrom {
  return !!p && p.shortName in CURRENT_TAG && /^\d/.test(p.tag)
}

// Used by findingSupportsFix to decide whether to offer the fix.
export function dockerfileBumpSupported(lineContent: string | null): boolean {
  if (!lineContent) return false
  return bumpable(parseFrom(lineContent))
}

export type DockerfileBumpInput = {
  finding: IaCFinding
  fileContent: string
}

export type DockerfileBumpResult = {
  patches: { path: string; content: string }[]
  newRef: string
}

export function applyDockerfileBaseImageBump(
  input: DockerfileBumpInput,
): DockerfileBumpResult {
  const lines = input.fileContent.split("\n")
  // Prefer the recorded line; fall back to matching the recorded lineContent
  // in case line numbers drifted between scan and fix.
  let idx = input.finding.lineNumber ? input.finding.lineNumber - 1 : -1
  if (!bumpable(parseFrom(lines[idx] ?? ""))) {
    const target = input.finding.lineContent?.trim()
    idx = lines.findIndex((l) => (target ? l.trim() === target : false) && bumpable(parseFrom(l)))
    if (idx < 0) idx = lines.findIndex((l) => bumpable(parseFrom(l)))
  }
  const line = lines[idx]
  const p = parseFrom(line ?? "")
  if (!bumpable(p)) {
    throw new Error("Dockerfile base-image bump: no supported EOL FROM line found")
  }
  const newVersion = CURRENT_TAG[p.shortName]
  const newTag = p.tag.replace(/^\d+(?:\.\d+)*/, newVersion)
  const oldRef = `${p.imagePart}:${p.tag}`
  const newRef = `${p.imagePart}:${newTag}`
  lines[idx] = line.replace(oldRef, newRef)
  return {
    patches: [{ path: input.finding.filePath, content: lines.join("\n") }],
    newRef,
  }
}
