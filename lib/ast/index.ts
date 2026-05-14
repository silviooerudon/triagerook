// Entry point for the AST-based SAST layer (FASE A).
//
// Each rule self-registers when its module loads, so importing this
// barrel is enough to populate the runner. The scan pipeline calls
// runAstRules() once per file alongside the existing regex code-vulns
// pass.
//
// Adding a new rule:
//   1. Create lib/ast/rules/<name>.ts
//   2. Call registerAstRule(...) at module scope
//   3. Re-export from here so the import statement below picks it up
//
// Rules are intentionally NOT lazy — the import side-effect is the
// registration mechanism, and lazy loading would skip them.

import "./rules/sql-injection"
import "./rules/command-injection"
import "./rules/path-traversal"
import "./rules/react-xss"
import "./rules/ssrf"
import "./rules/weak-crypto"
import "./rules/jwt-issues"
import "./rules/dynamic-eval"

export { runAstRules } from "./runner"
export type { AstRule, AstRuleHit } from "./runner"
