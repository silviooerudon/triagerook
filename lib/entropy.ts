import type { SecretFinding } from "./types"

/**
 * Shannon entropy of a string (in bits per character). Values:
 *   • English text  ≈ 3.5
 *   • Base64 secret ≈ 5.0+
 *   • UUID          ≈ 4.0 (hex, 128 bits of randomness)
 *   • Hex SHA256    ≈ 4.0
 */
function shannonEntropy(s: string): number {
  if (!s) return 0
  const counts: Record<string, number> = {}
  for (const ch of s) counts[ch] = (counts[ch] ?? 0) + 1
  let entropy = 0
  const len = s.length
  for (const ch in counts) {
    const p = counts[ch] / len
    entropy -= p * Math.log2(p)
  }
  return entropy
}

// Key names that strongly imply the value is a secret
const SECRET_KEY_REGEX = /\b(pass(?:wd|word)?|secret|private[_-]?key|api[_-]?key|access[_-]?key|auth[_-]?token|bearer|session[_-]?key|client[_-]?secret|service[_-]?key|encryption[_-]?key|signing[_-]?key|webhook[_-]?secret|jwt[_-]?secret|db[_-]?password|database[_-]?url)\b/i

// Values that are obviously placeholders, not real secrets
const PLACEHOLDER_REGEX =
  /^(your[-_]?[a-z]+[-_]?(here|key|token|secret|goes[-_]?here)|xxx+|placeholder|example|changeme|todo|n\/a|na|none|null|undefined|dummy|fake|test|mock|sample|demo|enter[-_]?your|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|%[a-z0-9_]+%)$/i

// Config-like file extensions where we expect KEY=VALUE or KEY: VALUE lines
const SCANNABLE_EXTS = new Set([
  "env",
  "envrc",
  "ini",
  "conf",
  "cfg",
  "config",
  "properties",
  "toml",
  "yaml",
  "yml",
  "json", // we only read shallow KV pairs
])

const MIN_ENTROPY = 4.0
const MIN_LENGTH = 20
const MAX_LENGTH = 200

type KVLine = {
  key: string
  value: string
  lineNumber: number
  raw: string
}

function extensionOf(path: string): string {
  const lower = path.toLowerCase()
  const dot = lower.lastIndexOf(".")
  if (dot < 0) return ""
  return lower.slice(dot + 1)
}

function basename(path: string): string {
  return path.split("/").pop() ?? path
}

function isScannableFile(path: string): boolean {
  const ext = extensionOf(path)
  if (SCANNABLE_EXTS.has(ext)) return true
  const name = basename(path)
  return /^\.env(\.[A-Za-z0-9_-]+)?$/i.test(name) || /^\.?envrc$/i.test(name)
}

function parseKVLines(content: string): KVLine[] {
  const lines = content.split("\n")
  const kv: KVLine[] = []
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]
    const stripped = raw.trimStart()
    if (stripped === "" || stripped.startsWith("#") || stripped.startsWith(";") || stripped.startsWith("//")) {
      continue
    }

    const kvMatch =
      stripped.match(/^["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]\s*(.+?)\s*$/) ??
      null
    if (!kvMatch) continue

    let value = kvMatch[2].trim()
    // Strip surrounding quotes
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1)
    }
    // Strip trailing inline comments (common in .env/ini)
    const commentIdx = value.search(/\s+#/)
    if (commentIdx > 0) value = value.slice(0, commentIdx).trim()

    kv.push({
      key: kvMatch[1],
      value,
      lineNumber: i + 1,
      raw,
    })
  }
  return kv
}

function valueLooksLikePlaceholder(value: string): boolean {
  if (PLACEHOLDER_REGEX.test(value)) return true
  // URL without credentials — keep (URL-with-password is caught by regex layer)
  if (/^https?:\/\/[^/]+(\/[^\s]*)?$/i.test(value) && !/@/.test(value)) return true
  // IP addresses
  if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(value)) return true
  // Pure digits — port numbers, counts
  if (/^\d+$/.test(value) && value.length < 20) return true
  // Boolean / common literals
  if (/^(true|false|yes|no|on|off|enabled|disabled|production|development|staging|local)$/i.test(value)) return true
  // Semantic version
  if (/^v?\d+\.\d+(\.\d+)?([.-][A-Za-z0-9._-]+)?$/.test(value)) return true
  // Path-like
  if (/^[./~][A-Za-z0-9._/-]+$/.test(value) && !value.includes(" ")) return true
  return false
}

function maskValue(value: string): string {
  if (value.length <= 8) return "•".repeat(value.length)
  return value.slice(0, 4) + "•".repeat(value.length - 8) + value.slice(-4)
}

/**
 * Scan a single file's content for likely generic secrets based on key name +
 * value entropy. Intended for .env/ini/yaml/properties files.
 */
export function findEntropySecrets(
  content: string,
  filePath: string,
  likelyTestFixture: boolean,
): SecretFinding[] {
  if (!isScannableFile(filePath)) return []

  const findings: SecretFinding[] = []
  const seen = new Set<string>()

  for (const { key, value, lineNumber, raw } of parseKVLines(content)) {
    if (value.length < MIN_LENGTH || value.length > MAX_LENGTH) continue
    if (valueLooksLikePlaceholder(value)) continue
    if (!SECRET_KEY_REGEX.test(key)) continue

    const entropy = shannonEntropy(value)
    if (entropy < MIN_ENTROPY) continue

    // De-dupe same value appearing multiple times in same file
    const fingerprint = `${key}=${value.slice(0, 10)}`
    if (seen.has(fingerprint)) continue
    seen.add(fingerprint)

    // Mask BEFORE truncating — if `value` extends past the 200-char window,
    // truncate-first would leave a partial copy of the literal secret in
    // `lineContent` (persisted to the DB and surfaced via API). Splitting on
    // the value lets us replace every occurrence safely (regex-special chars
    // in the value cannot break the replacement).
    const masked = maskValue(value)
    const fullSafeLine = raw.split(value).join(masked)
    const safeLine =
      fullSafeLine.length > 200 ? fullSafeLine.slice(0, 200) + "…" : fullSafeLine

    findings.push({
      patternId: "entropy-high-secret",
      patternName: "High-entropy value in secret-like key",
      severity: entropy >= 4.5 ? "high" : "medium",
      description: `Value assigned to "${key}" has high entropy (${entropy.toFixed(
        2,
      )} bits/char) and the key name matches a common secret naming pattern. This is likely a real credential, though custom formats may be missed by dedicated regexes.`,
      filePath,
      lineNumber,
      lineContent: safeLine.trim(),
      likelyTestFixture,
    })
  }

  return findings
}
