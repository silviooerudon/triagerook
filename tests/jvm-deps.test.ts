import { describe, it, expect } from "vitest"
import { parsePomXml, parseGradle } from "@/lib/jvm-deps"

describe("parsePomXml", () => {
  it("extracts groupId:artifactId@version from <dependency> blocks", () => {
    const pom = `
      <project>
        <dependencies>
          <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
          </dependency>
          <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>30.0-jre</version>
          </dependency>
        </dependencies>
      </project>`
    const deps = parsePomXml(pom)
    expect(deps).toContainEqual({
      name: "org.apache.logging.log4j:log4j-core",
      version: "2.14.1",
      source: "pom.xml",
    })
    expect(deps).toContainEqual({
      name: "com.google.guava:guava",
      version: "30.0-jre",
      source: "pom.xml",
    })
  })

  it("skips property-interpolated versions it can't resolve", () => {
    const pom = `<dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>\${spring.version}</version>
    </dependency>`
    expect(parsePomXml(pom)).toHaveLength(0)
  })

  it("skips blocks with no version (BOM-managed)", () => {
    const pom = `<dependency>
      <groupId>org.example</groupId>
      <artifactId>managed</artifactId>
    </dependency>`
    expect(parsePomXml(pom)).toHaveLength(0)
  })
})

describe("parseGradle", () => {
  it("parses the string coordinate form (Groovy + Kotlin)", () => {
    const gradle = `
      dependencies {
        implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
        api("com.fasterxml.jackson.core:jackson-databind:2.9.8")
        testImplementation 'junit:junit:4.13'
      }`
    const deps = parseGradle(gradle)
    expect(deps).toContainEqual({
      name: "org.apache.logging.log4j:log4j-core",
      version: "2.14.1",
      source: "build.gradle",
    })
    expect(deps).toContainEqual({
      name: "com.fasterxml.jackson.core:jackson-databind",
      version: "2.9.8",
      source: "build.gradle",
    })
    expect(deps.map((d) => d.name)).toContain("junit:junit")
  })

  it("parses the map form", () => {
    const gradle = `implementation group: 'commons-collections', name: 'commons-collections', version: '3.2.1'`
    expect(parseGradle(gradle)).toContainEqual({
      name: "commons-collections:commons-collections",
      version: "3.2.1",
      source: "build.gradle",
    })
  })

  it("skips dynamic/interpolated versions", () => {
    const gradle = `
      implementation "org.example:lib:1.+"
      implementation "org.example:lib2:$kotlinVersion"
      implementation "org.example:lib3:latest.release"`
    expect(parseGradle(gradle)).toHaveLength(0)
  })

  it("ignores a coordinate with a classifier but keeps group:artifact:version", () => {
    const gradle = `implementation 'org.example:lib:1.2.3:linux-x86_64'`
    expect(parseGradle(gradle)).toContainEqual({
      name: "org.example:lib",
      version: "1.2.3",
      source: "build.gradle",
    })
  })
})
