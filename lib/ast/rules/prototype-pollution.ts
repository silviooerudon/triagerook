import { SyntaxKind, type SourceFile } from "ts-morph"
import {
  getCallCalleeName,
  isUserInputExpression,
  lineContentOf,
  lineOf,
} from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Prototype pollution lands when an attacker-controlled object is merged
// into a target object by a routine that DOESN'T sanitise the `__proto__`
// key. The recursive merges in lodash/underscore are the classic offender;
// Object.assign is shallow but if the target is later spread into a
// constructor input it can still propagate. We focus on the recursive
// merge sinks because they have the highest hit-rate / lowest FP.
const RECURSIVE_MERGE_LAST_SEGMENT = /^(?:merge|mergeWith|defaultsDeep|set|setWith)$/

// Identifier names commonly bound to lodash / underscore / hoek. Used to
// distinguish `_.merge(target, src)` from a userland `someObj.merge(...)`.
const LIBRARY_MERGE_OBJECTS = new Set([
  "_",
  "lodash",
  "ld",
  "L",
  "Hoek",
  "Object",
])

const PROTO_POLLUTION_RULE: AstRule = {
  id: "ast/prototype-pollution-merge-user-input",
  name: "Prototype pollution: deep merge / assign with user-controlled object",
  severity: "high",
  category: "prototype-pollution",
  cwe: "CWE-1321",
  description:
    "A deep-merge function (lodash.merge / .mergeWith / .defaultsDeep / .set / .setWith) was called with a source object sourced from req.body, req.query, req.params, req.headers, ctx.request, or `userInput`. An attacker payload `{ \"__proto__\": { \"isAdmin\": true } }` pollutes Object.prototype globally on most lodash versions. Either upgrade to a patched version (lodash >= 4.17.20 with prototype-traversal disabled by default), validate the payload shape with Zod / Joi BEFORE merging, or use `Object.create(null)` as the target so the prototype chain isn't reachable.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const name = getCallCalleeName(call)
      if (!name) continue
      const parts = name.split(".")
      if (parts.length !== 2) continue
      const [obj, method] = parts
      if (!LIBRARY_MERGE_OBJECTS.has(obj)) continue
      if (obj === "Object" && method !== "assign") continue
      if (obj !== "Object" && !RECURSIVE_MERGE_LAST_SEGMENT.test(method)) continue

      const args = call.getArguments()
      if (args.length < 2) continue
      // For Object.assign(target, ...sources), the FIRST arg is the
      // mutating target. We flag if ANY non-target arg is user input.
      // For lodash, same: the first arg is the destination object.
      for (let i = 1; i < args.length; i++) {
        if (isUserInputExpression(args[i])) {
          hits.push({
            lineNumber: lineOf(call),
            lineContent: lineContentOf(call, sourceFile),
          })
          break
        }
      }
    }
    return hits
  },
}

registerAstRule(PROTO_POLLUTION_RULE)

export { PROTO_POLLUTION_RULE }
