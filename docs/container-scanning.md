# Container image CVE scanning (Trivy SARIF)

TriageRook's SCA already covers your **application** dependencies (npm, PyPI,
Go, RubyGems, Maven/Gradle, Composer) from their lockfiles, and flags
**end-of-life base images** statically. What a static scan *can't* see is the
CVEs in the **OS packages** baked into your built image (openssl, glibc, zlib,
…) — that needs the actual image, which only exists after `docker build`.

Rather than run a heavyweight image scanner ourselves, TriageRook **ingests the
result you already produce in CI**. Run [Trivy](https://trivy.dev) (free, OSS)
against your image, commit the SARIF report, and TriageRook folds its findings
into the scan under a **Container image** section.

## What it costs

- **Nothing extra on TriageRook.** We just read and parse the committed file.
- **Near-zero for you.** Trivy is Apache-2.0 (no license). It runs in your
  existing CI and downloads a small, cacheable vuln DB — no API key.

## Setup

Add a Trivy step to your CI that writes a SARIF report to one of the paths
TriageRook looks for (in order):

```
trivy-results.sarif
trivy.sarif
.triagerook/trivy.sarif
.github/trivy-results.sarif
```

### GitHub Actions example

```yaml
name: container-scan
on:
  schedule: [{ cron: "0 6 * * 1" }]   # weekly is plenty; CVE DBs change daily but image rebuilds don't
  workflow_dispatch:
jobs:
  trivy:
    runs-on: ubuntu-latest
    permissions:
      contents: write                 # to commit the report back
    steps:
      - uses: actions/checkout@v4
      - name: Scan image with Trivy
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: ghcr.io/your-org/your-app:latest
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH,MEDIUM
      - name: Commit the report
        run: |
          git config user.name  "trivy-bot"
          git config user.email "trivy-bot@users.noreply.github.com"
          git add trivy-results.sarif
          git commit -m "chore: update Trivy container scan" || echo "no changes"
          git push
```

> Prefer not to commit generated files? Point the Trivy step at
> `.triagerook/trivy.sarif` and keep that path out of your app build — it only
> needs to exist on the default branch for TriageRook to read it.

## How TriageRook reads it

- Only **vulnerability** results are ingested (CVE-/GHSA-/distro-advisory rule
  ids, or rules tagged `vulnerability`). Trivy *misconfiguration* output is
  ignored here — IaC is covered by TriageRook's own Dockerfile/K8s/Terraform/
  CloudFormation/Helm detectors.
- Severity comes from the report (`Severity:` line, else the rule's CVSS
  `security-severity`, else the SARIF level).
- Findings appear as **Container** dependencies, scored and prioritised like
  any other vulnerable dependency.
- A committed-but-broken SARIF is surfaced as a degraded-scan banner rather
  than silently read as "image is clean".

## Note on overlap

Trivy scans OS **and** language packages, so a few findings may overlap with
TriageRook's lockfile SCA. They're kept in their own **Container image** section
(not merged) so the provenance stays honest — that section is "what the built
image actually contains", which is strictly more than the manifests declare.
