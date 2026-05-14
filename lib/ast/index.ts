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
//
// IMPORTANT — README claims "28 AST rules". That number counts
// registered rules, NOT files in this barrel. `jwt-issues.ts` registers
// two rules (JWT_NO_EXPIRES_IN + JWT_HARDCODED_SECRET); every other
// file registers one. So: 27 files × 1 rule + 1 file × 2 rules = 28.
// `grep -rEc "^registerAstRule\(" lib/ast/rules/` is the source of
// truth — keep it in sync with the README.

import "./rules/sql-injection"
import "./rules/command-injection"
import "./rules/path-traversal"
import "./rules/react-xss"
import "./rules/ssrf"
import "./rules/weak-crypto"
import "./rules/jwt-issues"
import "./rules/dynamic-eval"
import "./rules/cors-misconfig"
import "./rules/prototype-pollution"
import "./rules/log-credentials"
import "./rules/open-redirect"
import "./rules/redos"
import "./rules/session-config"
import "./rules/timing-unsafe-compare"
import "./rules/math-random-token"
import "./rules/nosql-injection"
import "./rules/template-injection"
import "./rules/hardcoded-admin-creds"
import "./rules/wildcard-cors-header"
import "./rules/reflected-xss-send"
import "./rules/weak-cipher"
import "./rules/hardcoded-encryption-key"
import "./rules/insecure-cookie-set"
import "./rules/insecure-websocket-protocol"
import "./rules/xxe-xml-parser"
import "./rules/jwt-decode-without-verify"

export { runAstRules } from "./runner"
export type { AstRule, AstRuleHit } from "./runner"
