import { Project, ScriptKind, SourceFile } from "ts-morph"

// Thin wrapper around ts-morph for the AST-based detector layer. We use
// an in-memory Project (no tsconfig, no fs scanning) because each scan
// gets the file contents already in memory from the tree fetch — there
// is no project graph to walk.
//
// Performance note: parsing the same source twice (once for SQL injection,
// once for command injection, etc.) is wasteful. The runner below caches
// the SourceFile per (path, content hash) so multiple rules amortise the
// parse cost.

const JS_TS_EXTENSIONS = new Set([
  "js",
  "jsx",
  "ts",
  "tsx",
  "mjs",
  "cjs",
  "mts",
  "cts",
])

export type SupportedLanguage = "js" | "ts"

export function detectAstLanguage(filePath: string): SupportedLanguage | null {
  const lower = filePath.toLowerCase()
  const ext = lower.slice(lower.lastIndexOf(".") + 1)
  if (!JS_TS_EXTENSIONS.has(ext)) return null
  if (ext === "ts" || ext === "tsx" || ext === "mts" || ext === "cts") return "ts"
  return "js"
}

function scriptKindFor(filePath: string): ScriptKind {
  const lower = filePath.toLowerCase()
  if (lower.endsWith(".tsx")) return ScriptKind.TSX
  if (lower.endsWith(".jsx")) return ScriptKind.JSX
  if (lower.endsWith(".ts") || lower.endsWith(".mts") || lower.endsWith(".cts")) {
    return ScriptKind.TS
  }
  return ScriptKind.JS
}

// Soft ceiling so a hostile / generated megafile cannot stall a scan.
// 200 KB covers every legitimate human-written source we have seen in
// scans so far. Bigger files are likely build output or fixtures and
// we'd false-positive heavily on them anyway.
const MAX_AST_FILE_BYTES = 200 * 1024

export type AstParseResult =
  | { kind: "ok"; sourceFile: SourceFile; language: SupportedLanguage }
  | { kind: "skip"; reason: "unsupported" | "too-large" | "parse-error" }

// One Project instance per parse: cheapest way to keep node-tree garbage
// collectable. Reusing a Project across files keeps stale SourceFiles in
// memory and grows the working set unboundedly during a scan.
export function parseAst(filePath: string, content: string): AstParseResult {
  const language = detectAstLanguage(filePath)
  if (!language) return { kind: "skip", reason: "unsupported" }

  // UTF-8 byte length, not char length: BMP chars are 1 byte, but emojis
  // and CJK go up to 4. Cheap conservative check uses Buffer.
  if (Buffer.byteLength(content, "utf8") > MAX_AST_FILE_BYTES) {
    return { kind: "skip", reason: "too-large" }
  }

  try {
    const project = new Project({
      useInMemoryFileSystem: true,
      skipAddingFilesFromTsConfig: true,
      compilerOptions: {
        allowJs: true,
        noEmit: true,
        // We never resolve modules from disk; rules walk the AST only.
        moduleResolution: 100, // ModuleResolutionKind.Bundler
      },
    })
    const sourceFile = project.createSourceFile(filePath, content, {
      scriptKind: scriptKindFor(filePath),
      overwrite: true,
    })
    return { kind: "ok", sourceFile, language }
  } catch {
    // Syntactically invalid JS/TS files happen (in-progress edits, AI
    // output that almost-but-not-quite parses). Skip rather than crash
    // the scan — this is observation tooling, not a compiler.
    return { kind: "skip", reason: "parse-error" }
  }
}
