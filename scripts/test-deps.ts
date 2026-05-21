import { scanDependencies } from "../lib/deps"
import { scanPythonDependencies } from "../lib/python-deps"

const TOKEN = process.env.TEST_GITHUB_TOKEN ?? null
const OWNER = process.env.TEST_OWNER ?? "silviooerudon"
const REPO = process.env.TEST_REPO ?? "triagerook"

async function main() {
  console.log(`Scanning ${OWNER}/${REPO}...`)

  const npmResult = await scanDependencies(OWNER, REPO, TOKEN)
  console.log(
    `npm: ${npmResult.vulns.length} vulnerabilities, ${npmResult.lifecycleIssues.length} suspicious lifecycle scripts`,
  )

  const pyResult = await scanPythonDependencies(OWNER, REPO, TOKEN)
  console.log(`PyPI: ${pyResult.findings.length} vulnerabilities`)

  console.log(
    JSON.stringify(
      { npm: npmResult, python: pyResult },
      null,
      2,
    ),
  )
}

main().catch(console.error)
