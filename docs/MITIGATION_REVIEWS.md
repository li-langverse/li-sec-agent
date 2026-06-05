# Mitigation-first PR reviews

SecAgent reviews pair every **finding** with a concrete **mitigation** — CodeRabbit-style actionable comments with a security focus.

## UX goals

| Principle | Behavior |
|-----------|----------|
| Actionable | Every finding includes a **Suggested fix** section |
| Localized | `suggested_patch` when the change is small and clear |
| Guided | Text-only remediation when architecture or policy decisions are needed |
| Traceable | CWE links + OWASP cheat sheets in `references[]` |
| Honest effort | `effort: low\|medium\|high` sets reviewer expectations |

## Severity rubric

| Severity | When to use | Mitigation style |
|----------|-------------|------------------|
| **critical** | Exploitable secret, RCE, auth bypass | Patch + rotation steps; flag immediately |
| **high** | Injection, XSS, IDOR with clear path | Prefer `suggested_patch` + parameterized/sanitize pattern |
| **medium** | Weak crypto, missing validation, misconfig | Guidance + config example; alternatives listed |
| **low** | Defense-in-depth gaps | Short fix; optional patch |
| **info** | Hardening opportunities | One-paragraph guidance; no patch required |

## When to suggest patch vs guidance

**Use `suggested_patch`** when:

- The fix is a localized diff hunk (1–20 lines)
- The secure pattern is unambiguous (parameterized query, `textContent`, `process.env`)
- The reviewer can apply the patch without product decisions

**Use guidance only** when:

- Fix spans multiple services (auth model, tenancy)
- Dependency upgrade needs compatibility testing
- Policy choice (CSP strictness, rate limits)

Always include `alternative_approaches[]` when multiple valid fixes exist.

## PR comment layout

1. Summary table (severity, location, issue, fix effort)
2. Per-issue blocks: finding details → **Suggested fix** → optional diff fence → references

See [PR_INTEGRATION.md](./PR_INTEGRATION.md) for GitHub API wiring and a full markdown example.

## Telemetry (privacy)

- `mitigation_suggested` events store `mitigation_hash` (SHA-256 of title + description + effort + patch)
- Raw patches are **not** written to `telemetry_events` by default
- Full mitigations persist in `mitigations` table linked to `findings`

## Premium tier

Mitigation quality (patch accuracy, CWE mapping, low false-positive rate) is the **premium differentiator**:

- **Free / OSS**: summary findings table
- **Team+**: inline comments with `suggested_patch`
- **Business+**: custom rulepacks + mitigation templates per org

See [README](../README.md) monetization section.

## Training loop

Reference corpus negatives teach safe patterns; positives include expected mitigations in SFT export. See [REFERENCE_DATABASE.md](./REFERENCE_DATABASE.md).

Golden examples: `eval/mitigation-examples.json`.
