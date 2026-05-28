// Framework detection — the "context" in context-aware SAST.
//
// A bare `DEBUG = True` or `csrf().disable()` is only a meaningful finding
// when we know the framework it belongs to. Detecting the active frameworks
// from the repo's manifests lets the framework-rule layer (lib/framework-
// rules.ts) gate its checks, so we flag `DEBUG = True` as a Django production
// risk only when Django is actually a dependency — not on every variable
// named DEBUG in any language.

export type Framework =
  | "nextjs"
  | "express"
  | "nestjs"
  | "django"
  | "flask"
  | "fastapi"
  | "spring"
  | "laravel"
  | "rails"

// The manifest files we read to infer frameworks. All optional — a repo
// usually only has one or two.
export type Manifests = {
  packageJson?: string | null
  requirements?: string | null // requirements.txt
  pyproject?: string | null // pyproject.toml
  pipfile?: string | null // Pipfile
  pom?: string | null // pom.xml
  gradle?: string | null // build.gradle(.kts)
  gemfile?: string | null // Gemfile
  composer?: string | null // composer.json
}

// Manifest filenames we fetch, mapped to the Manifests key they populate.
export const MANIFEST_FILES: Record<string, keyof Manifests> = {
  "package.json": "packageJson",
  "requirements.txt": "requirements",
  "pyproject.toml": "pyproject",
  Pipfile: "pipfile",
  "pom.xml": "pom",
  "build.gradle": "gradle",
  "build.gradle.kts": "gradle",
  Gemfile: "gemfile",
  "composer.json": "composer",
}

function npmHasDep(packageJson: string, name: string): boolean {
  try {
    const json = JSON.parse(packageJson) as {
      dependencies?: Record<string, string>
      devDependencies?: Record<string, string>
      peerDependencies?: Record<string, string>
    }
    return Boolean(
      json.dependencies?.[name] ??
        json.devDependencies?.[name] ??
        json.peerDependencies?.[name],
    )
  } catch {
    // Fall back to a substring check on malformed JSON.
    return new RegExp(`"${name.replace(/[/\\^$*+?.()|[\]{}]/g, "\\$&")}"`).test(packageJson)
  }
}

/**
 * Infer the set of web frameworks in use from the repo's manifests. Pure and
 * synchronous so it's trivially testable; the caller is responsible for
 * fetching the manifest contents.
 */
export function detectFrameworks(manifests: Manifests): Set<Framework> {
  const fw = new Set<Framework>()
  const pkg = manifests.packageJson

  if (pkg) {
    if (npmHasDep(pkg, "next")) fw.add("nextjs")
    if (npmHasDep(pkg, "express")) fw.add("express")
    if (npmHasDep(pkg, "@nestjs/core")) fw.add("nestjs")
  }

  // Python: requirements.txt / pyproject.toml / Pipfile are plain text; a
  // case-insensitive name match is enough to know the framework is present.
  const py = [manifests.requirements, manifests.pyproject, manifests.pipfile]
    .filter(Boolean)
    .join("\n")
    .toLowerCase()
  if (py) {
    if (/\bdjango\b/.test(py)) fw.add("django")
    if (/\bflask\b/.test(py)) fw.add("flask")
    if (/\bfastapi\b/.test(py)) fw.add("fastapi")
  }

  const jvm = [manifests.pom, manifests.gradle].filter(Boolean).join("\n")
  if (jvm && /spring-boot|springframework/i.test(jvm)) fw.add("spring")

  if (manifests.composer && /"laravel\/framework"/.test(manifests.composer)) {
    fw.add("laravel")
  }

  if (manifests.gemfile && /^\s*gem\s+["']rails["']/m.test(manifests.gemfile)) {
    fw.add("rails")
  }

  return fw
}
