import type { IaCFinding, Severity } from "./types"

// Docker base-image risk scanner.
//
// A static fetch can't pull an image and enumerate its OS-package CVEs the way
// Trivy/Grype do — that needs the image layers. The high-signal *static*
// equivalent is end-of-life detection: once a base image's distro/runtime
// release stops receiving security updates, it accumulates unpatched CVEs by
// definition. Pinning to an EOL `node:16` / `python:3.7` / `debian:9` /
// `ubuntu:18.04` is the single biggest base-image risk we can prove from the
// Dockerfile alone, so that's what we flag.
//
// This is intentionally NOT a full layer CVE scan (documented, not silent):
// it reports EOL/unsupported base images, not the specific CVEs inside them.

type EolRule = {
  // The short image name (last path segment, lowercased): node, python, debian…
  image: string
  // Given a parsed tag, return an EOL ISO date if this tag is an EOL release,
  // else null. `tag` is already lowercased and digest-stripped.
  eolDate: (tag: string) => string | null
}

// Extract the leading numeric version from a tag like "18", "3.7-slim",
// "16.04", "3.9.18-alpine" → [major, minor] numbers (minor may be NaN).
function tagVersion(tag: string): { major: number; minor: number } {
  const m = tag.match(/^(\d+)(?:\.(\d+))?/)
  if (!m) return { major: NaN, minor: NaN }
  return { major: Number(m[1]), minor: m[2] ? Number(m[2]) : NaN }
}

// Curated EOL dataset. Dates are the published end-of-security-support dates
// (endoflife.date). Conservative: only majors/releases that are unambiguously
// past EOL are listed; current/LTS releases are intentionally absent so we
// don't cry wolf. Revisit periodically as releases age out.
const EOL_RULES: EolRule[] = [
  {
    image: "node",
    eolDate: (tag) => {
      const { major } = tagVersion(tag)
      const dates: Record<number, string> = {
        8: "2019-12-31", 9: "2018-06-30", 10: "2021-04-30", 11: "2019-06-01",
        12: "2022-04-30", 13: "2020-06-01", 14: "2023-04-30", 15: "2021-06-01",
        16: "2023-09-11", 17: "2022-06-01", 18: "2025-04-30", 19: "2023-06-01",
        21: "2024-06-01",
      }
      return dates[major] ?? null
    },
  },
  {
    image: "python",
    eolDate: (tag) => {
      const { major, minor } = tagVersion(tag)
      if (major === 2) return "2020-01-01"
      if (major === 3 && !Number.isNaN(minor)) {
        const dates: Record<number, string> = {
          0: "2009-06-27", 1: "2012-04-09", 2: "2013-05-09", 3: "2017-09-29",
          4: "2019-03-18", 5: "2020-09-30", 6: "2021-12-23", 7: "2023-06-27",
          8: "2024-10-31", 9: "2025-10-31",
        }
        return dates[minor] ?? null
      }
      return null
    },
  },
  {
    image: "ruby",
    eolDate: (tag) => {
      const { major, minor } = tagVersion(tag)
      if (major === 2) return "2023-03-31"
      if (major === 3 && minor === 0) return "2024-03-31"
      return null
    },
  },
  {
    image: "php",
    eolDate: (tag) => {
      const { major, minor } = tagVersion(tag)
      if (major < 8) return "2022-11-28"
      if (major === 8 && (minor === 0 || minor === 1)) return "2023-11-26"
      return null
    },
  },
  {
    image: "golang",
    eolDate: (tag) => {
      // Go supports only the latest two majors; <=1.20 is unsupported.
      const { major, minor } = tagVersion(tag)
      if (major === 1 && !Number.isNaN(minor) && minor <= 20) return "2024-02-06"
      return null
    },
  },
  {
    image: "debian",
    eolDate: (tag) => {
      const byName: Record<string, string> = {
        wheezy: "2018-05-31", jessie: "2020-06-30", stretch: "2022-06-30",
        buster: "2024-06-30",
      }
      for (const [name, date] of Object.entries(byName)) {
        if (tag.startsWith(name)) return date
      }
      const { major } = tagVersion(tag)
      const byNum: Record<number, string> = {
        7: "2018-05-31", 8: "2020-06-30", 9: "2022-06-30", 10: "2024-06-30",
      }
      return byNum[major] ?? null
    },
  },
  {
    image: "ubuntu",
    eolDate: (tag) => {
      const byName: Record<string, string> = {
        trusty: "2019-04-30", xenial: "2021-04-30", bionic: "2023-05-31",
        focal: "2025-04-30",
      }
      for (const [name, date] of Object.entries(byName)) {
        if (tag.startsWith(name)) return date
      }
      const map: Record<string, string> = {
        "14.04": "2019-04-30", "16.04": "2021-04-30", "18.04": "2023-05-31",
        "20.04": "2025-04-30",
      }
      const v = tag.match(/^(\d+\.\d+)/)?.[1]
      return v ? map[v] ?? null : null
    },
  },
  {
    image: "centos",
    // CentOS Linux is fully discontinued — every tag is unsupported.
    eolDate: () => "2024-06-30",
  },
  {
    image: "alpine",
    eolDate: (tag) => {
      // Alpine supports ~the last two minor releases (~2yr). <=3.16 is EOL.
      const { major, minor } = tagVersion(tag)
      if (major === 3 && !Number.isNaN(minor) && minor <= 16) return "2024-05-23"
      return null
    },
  },
]

type ParsedFrom = { image: string; tag: string; raw: string; lineIndex: number }

// Parse FROM directives, resolving multi-stage references. Returns only lines
// that reference a real registry image (stage aliases and `scratch` skipped).
export function parseFromLines(lines: string[]): ParsedFrom[] {
  const stageNames = new Set<string>()
  const out: ParsedFrom[] = []
  lines.forEach((line, lineIndex) => {
    const m = line.match(/^\s*FROM\s+(.+?)\s*$/i)
    if (!m) return
    let rest = m[1]
    // Drop a leading --platform=... flag.
    rest = rest.replace(/^--platform=\S+\s+/i, "")
    // Split off "AS <stage>".
    const asMatch = rest.match(/\s+AS\s+(\S+)\s*$/i)
    let stageAlias: string | null = null
    if (asMatch) {
      stageAlias = asMatch[1].toLowerCase()
      rest = rest.slice(0, asMatch.index).trim()
    }
    const ref = rest.trim()
    const refLower = ref.toLowerCase()
    // FROM <previous-stage> — not an image.
    if (stageNames.has(refLower)) {
      if (stageAlias) stageNames.add(stageAlias)
      return
    }
    if (stageAlias) stageNames.add(stageAlias)
    if (refLower === "scratch" || ref.startsWith("$")) return
    // Strip digest, then split image:tag (tag is after the LAST colon that
    // isn't part of a registry host:port — registry ports come before a `/`).
    const noDigest = ref.split("@")[0]
    let image = noDigest
    let tag = ""
    const lastColon = noDigest.lastIndexOf(":")
    const lastSlash = noDigest.lastIndexOf("/")
    if (lastColon > lastSlash) {
      image = noDigest.slice(0, lastColon)
      tag = noDigest.slice(lastColon + 1)
    }
    const shortName = image.split("/").pop()!.toLowerCase()
    out.push({ image: shortName, tag: tag.toLowerCase(), raw: noDigest, lineIndex })
  })
  return out
}

function severityForEol(eol: string, now: Date): Severity {
  const ageDays = (now.getTime() - new Date(eol).getTime()) / 86_400_000
  if (ageDays < 0) return "low" // not yet EOL at scan time
  if (ageDays > 365) return "high" // a year+ of unpatched CVEs piling up
  return "medium"
}

// Scan a Dockerfile's FROM lines for end-of-life base images. `now` is
// injectable for deterministic tests.
export function scanDockerBaseImages(
  content: string,
  filePath: string,
  now: Date = new Date(),
): IaCFinding[] {
  const lines = content.split("\n")
  const findings: IaCFinding[] = []
  for (const from of parseFromLines(lines)) {
    if (!from.tag) continue // untagged → handled by the :latest rule
    const rule = EOL_RULES.find((r) => r.image === from.image)
    if (!rule) continue
    const eol = rule.eolDate(from.tag)
    if (!eol) continue
    if (new Date(eol).getTime() > now.getTime()) continue // not EOL yet
    findings.push({
      ruleId: "dockerfile-base-image-eol",
      ruleName: "End-of-life base image",
      severity: severityForEol(eol, now),
      category: "dockerfile",
      description: `Base image \`${from.raw}\` reached end-of-life on ${eol} and no longer receives security updates. Unpatched OS/runtime CVEs accumulate in every layer built on it.`,
      filePath,
      lineNumber: from.lineIndex + 1,
      lineContent: (lines[from.lineIndex] ?? "").trim().slice(0, 200) || null,
      remediation: `Upgrade \`${from.image}\` to a currently-supported release and rebuild. Pin to a digest once on a supported tag.`,
    })
  }
  return findings
}
