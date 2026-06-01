# TriageRook — Positioning

> Source of truth for product framing. The central angle is **CI/CD + identity
> security**: detecting identity and privilege misconfiguration that GitHub's
> native tooling does not cover. This angle drives both the Overview and the
> Positioning sections — TriageRook is not framed as a generic scanner.

---

## 1. Overview

### One-liner

**EN** — TriageRook finds the identity and privilege misconfigurations in your
GitHub repo and CI/CD pipeline that native GitHub tooling leaves uncovered —
in one click.

**PT** — O TriageRook encontra as configurações incorretas de identidade e
privilégio no seu repositório GitHub e pipeline de CI/CD que as ferramentas
nativas do GitHub deixam descobertas — em um clique.

### Paragraph

**EN** — Dependabot, secret scanning, and code scanning already cover dependency
CVEs and leaked credentials. TriageRook answers the question they don't: who can
escalate privilege in this repo, and is the CI/CD trust chain safe? It applies an
identity-security lens — OIDC trust misconfiguration, privilege-escalation paths
in workflows, admin-equivalent access — to the repository and its pipeline,
with secrets, dependency, supply-chain, and posture checks as supporting
coverage around that core.

**PT** — Dependabot, secret scanning e code scanning já cobrem CVEs de
dependência e credenciais vazadas. O TriageRook responde à pergunta que elas não
respondem: quem pode escalar privilégio neste repositório e a cadeia de confiança
do CI/CD está segura? Ele aplica um olhar de segurança de identidade —
configuração incorreta de trust OIDC, caminhos de escalada de privilégio em
workflows, acessos equivalentes a admin — ao repositório e ao seu pipeline, com
verificações de secrets, dependências, supply chain e postura como cobertura de
apoio ao redor desse núcleo.

---

## 2. Positioning & differentiators

### EN

TriageRook is a one-click security scanner for GitHub repositories, focused on
what native GitHub tooling does not cover: identity and privilege
misconfiguration in your repo and CI/CD pipeline.

GitHub's built-in tools (Dependabot, secret scanning, code scanning) handle
dependency CVEs and leaked credentials well — and GitHub's 2026 Actions roadmap
is closing the supply-chain gap further. TriageRook does not compete there. It
answers a different question: who can escalate privilege in this repo, and is the
CI/CD trust chain safe?

It detects OIDC trust misconfiguration, privilege-escalation paths in workflows,
and admin-equivalent access — the class of issue behind real-world CI/CD
supply-chain incidents, and the class that requires an identity-security lens to
catch. This is the core. Secrets, dependency, supply-chain and posture checks are
included as supporting coverage, not the headline.

What TriageRook is NOT: it is not DAST (it does not test a running application),
and it is not a replacement for deep AST-based SAST engines like CodeQL or
Semgrep. Its SAST layer is regex-based and intentionally lightweight.

Why it exists: built by an IAM/IGA specialist (10+ years, SailPoint/CyberArk), it
brings an identity-governance perspective to repository security that generic
scanners miss.

### PT

O TriageRook é um scanner de segurança one-click para repositórios GitHub,
focado no que as ferramentas nativas do GitHub não cobrem: configuração
incorreta de identidade e privilégio no repositório e no pipeline de CI/CD.

As ferramentas nativas do GitHub (Dependabot, secret scanning, code scanning)
tratam bem CVEs de dependência e credenciais vazadas — e o roadmap de Actions do
GitHub para 2026 fecha ainda mais essa lacuna de supply chain. O TriageRook não
compete nesse terreno. Ele responde a outra pergunta: quem pode escalar
privilégio neste repositório e a cadeia de confiança do CI/CD está segura?

Ele detecta configuração incorreta de trust OIDC, caminhos de escalada de
privilégio em workflows e acessos equivalentes a admin — a classe de problema por
trás de incidentes reais de supply chain em CI/CD, e a classe que exige um olhar
de segurança de identidade para ser detectada. Esse é o núcleo. As verificações
de secrets, dependências, supply chain e postura entram como cobertura de apoio,
não como a manchete.

O que o TriageRook NÃO é: não é DAST (não testa uma aplicação em execução) e não
substitui motores de SAST profundos baseados em AST como CodeQL ou Semgrep. Sua
camada de SAST é baseada em regex e intencionalmente leve.

Por que existe: construído por um especialista em IAM/IGA (10+ anos,
SailPoint/CyberArk), traz uma perspectiva de governança de identidade para a
segurança de repositórios que os scanners genéricos não enxergam.
