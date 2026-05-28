import { describe, it, expect } from "vitest"
import { detectFrameworks, type Framework } from "@/lib/framework-detect"
import { scanFrameworkRules, FRAMEWORK_RULES } from "@/lib/framework-rules"

describe("detectFrameworks", () => {
  it("detects npm frameworks from package.json deps", () => {
    const pkg = JSON.stringify({
      dependencies: { next: "15.0.0", express: "^4.18.0" },
      devDependencies: { "@nestjs/core": "^10.0.0" },
    })
    const fw = detectFrameworks({ packageJson: pkg })
    expect(fw.has("nextjs")).toBe(true)
    expect(fw.has("express")).toBe(true)
    expect(fw.has("nestjs")).toBe(true)
  })

  it("detects python frameworks from requirements / pyproject", () => {
    expect(detectFrameworks({ requirements: "Django==5.0\ngunicorn" }).has("django")).toBe(true)
    expect(detectFrameworks({ requirements: "flask>=3" }).has("flask")).toBe(true)
    expect(detectFrameworks({ pyproject: 'dependencies = ["fastapi"]' }).has("fastapi")).toBe(true)
  })

  it("detects JVM / PHP / Ruby frameworks", () => {
    expect(detectFrameworks({ pom: "<artifactId>spring-boot-starter-web</artifactId>" }).has("spring")).toBe(true)
    expect(detectFrameworks({ composer: '{"require":{"laravel/framework":"^11"}}' }).has("laravel")).toBe(true)
    expect(detectFrameworks({ gemfile: 'gem "rails", "~> 7.1"' }).has("rails")).toBe(true)
  })

  it("returns empty for unrelated manifests", () => {
    expect(detectFrameworks({ packageJson: '{"dependencies":{"lodash":"^4"}}' }).size).toBe(0)
    expect(detectFrameworks({}).size).toBe(0)
  })

  it("tolerates malformed package.json", () => {
    expect(detectFrameworks({ packageJson: '{ broken "next": }' }).has("nextjs")).toBe(true)
  })
})

const fw = (...f: Framework[]) => new Set<Framework>(f)

describe("scanFrameworkRules — gating", () => {
  it("does nothing when no frameworks are detected", () => {
    expect(scanFrameworkRules("DEBUG = True", "settings.py", new Set(), false)).toHaveLength(0)
  })

  it("flags Django DEBUG only when Django is present", () => {
    expect(scanFrameworkRules("DEBUG = True", "settings.py", fw("flask"), false)).toHaveLength(0)
    const found = scanFrameworkRules("DEBUG = True", "settings.py", fw("django"), false)
    expect(found.some((f) => f.ruleId === "django-debug-true")).toBe(true)
  })

  it("respects file language: a Django rule does not run on a .js file", () => {
    expect(scanFrameworkRules("DEBUG = True", "app.js", fw("django"), false)).toHaveLength(0)
  })
})

describe("scanFrameworkRules — representative rules", () => {
  it("Django: ALLOWED_HOSTS wildcard + csrf_exempt", () => {
    const ids = scanFrameworkRules(
      `ALLOWED_HOSTS = ['*']\n@csrf_exempt\ndef view(r): pass`,
      "views.py",
      fw("django"),
      false,
    ).map((f) => f.ruleId)
    expect(ids).toContain("django-allowed-hosts-wildcard")
    expect(ids).toContain("django-csrf-exempt")
  })

  it("Flask: app.run(debug=True)", () => {
    const found = scanFrameworkRules(`app.run(debug=True)`, "main.py", fw("flask"), false)
    expect(found[0]?.ruleId).toBe("flask-debug-run")
    expect(found[0]?.cwe).toBe("CWE-489")
  })

  it("FastAPI: wildcard CORS origins", () => {
    const found = scanFrameworkRules(`allow_origins=["*"]`, "main.py", fw("fastapi"), false)
    expect(found.some((f) => f.ruleId === "fastapi-cors-wildcard-credentials")).toBe(true)
  })

  it("Express: bare cors()", () => {
    const found = scanFrameworkRules(`app.use(cors())`, "server.js", fw("express"), false)
    expect(found.some((f) => f.ruleId === "express-cors-wildcard")).toBe(true)
  })

  it("Spring: csrf disabled + wildcard CrossOrigin", () => {
    const ids = scanFrameworkRules(
      `http.csrf().disable();\n@CrossOrigin(origins = "*")`,
      "Security.java",
      fw("spring"),
      false,
    ).map((f) => f.ruleId)
    expect(ids).toContain("spring-csrf-disabled")
    expect(ids).toContain("spring-cors-wildcard")
  })

  it("Spring: actuator expose-all in a properties file (any-language rule)", () => {
    const found = scanFrameworkRules(
      `management.endpoints.web.exposure.include=*`,
      "application.properties",
      fw("spring"),
      false,
    )
    expect(found.some((f) => f.ruleId === "spring-actuator-expose-all")).toBe(true)
  })

  it("Laravel: debug => true; Rails: skip CSRF", () => {
    expect(
      scanFrameworkRules(`'debug' => true,`, "app.php", fw("laravel"), false).some(
        (f) => f.ruleId === "laravel-app-debug-true",
      ),
    ).toBe(true)
    expect(
      scanFrameworkRules(
        `skip_before_action :verify_authenticity_token`,
        "controller.rb",
        fw("rails"),
        false,
      ).some((f) => f.ruleId === "rails-skip-csrf"),
    ).toBe(true)
  })

  it("does not flag safe config (DEBUG = False, scoped CORS)", () => {
    expect(scanFrameworkRules("DEBUG = False", "settings.py", fw("django"), false)).toHaveLength(0)
  })

  it("every rule carries a CWE and a framework", () => {
    for (const r of FRAMEWORK_RULES) {
      expect(r.cwe).toMatch(/^CWE-/)
      expect(r.framework.length).toBeGreaterThan(0)
    }
  })
})
