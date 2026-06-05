# li-sec-agent (deprecated)

> **This repository has moved.** Development continues at **[cap-jmk-launchpad/sec-agent](https://github.com/cap-jmk-launchpad/sec-agent)** under the Klaut homelab product suite.
>
> See [docs/MIGRATION_FROM_LI_SEC_AGENT.md](https://github.com/cap-jmk-launchpad/sec-agent/blob/main/docs/MIGRATION_FROM_LI_SEC_AGENT.md) for migration details, renamed paths, and deploy commands.

## Why

The security agent integrates with Klaut homelab services:

- CWE mirror — [cwe.klaut.pro](https://cwe.klaut.pro)
- Dependency-Track — [deps.klaut.pro](https://deps.klaut.pro)
- Vault — [vault.klaut.pro](https://vault.klaut.pro)

It belongs under [cap-jmk-launchpad](https://github.com/cap-jmk-launchpad), not `li-langverse`.

## Do not use this repo

- Do not open new PRs or issues here.
- Homelab deploys: clone `cap-jmk-launchpad/sec-agent` and run `.\scripts\deploy-staging.ps1`.
- Package name is now `klaut-sec-agent`; image `ghcr.io/cap-jmk-launchpad/klaut-sec-agent`.

## Historical note

Last active commit on this repo: mitigation-first PR reviews, reference corpus worker, and eval corpora. Full git history was merged into `sec-agent` `main` (2026-06-05).
