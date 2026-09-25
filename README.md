<p align="center">
  <img src="assets/morpheus-security-badge.png" width="180" alt="Morpheus Security badge">
</p>

# Morpheus Security

Deterministic OSV and GitHub advisory remediation for GitHub repositories. It runs as a nightly or
manually dispatched GitHub Action, opens one dependency-only pull request at a time per lockfile,
and merges only on a later run after the repository's explicitly named checks pass.

Morpheus Security uses no model, OpenAI API, local agent, or paid service.

## Trust model

This repository is public source, not a hosted service. The `morpheus-security` GitHub App used by
the maintainers is installed only on repositories they control. Other operators should register
their own GitHub App with the documented least-privilege permissions and keep its private key in
their own encrypted repository secrets. Do not install the maintainers' App expecting it to run a
service for you.

Read the [security and remediation policy](docs/policy.md), then follow the
[installation runbook](docs/installation.md).

## Supported delivery adapters

- npm `package-lock.json`
- pnpm `pnpm-lock.yaml`
- Python `uv.lock`

OSV detection may identify other ecosystems, but an unsupported lockfile fails closed instead of
inventing a package-manager mutation.

## Development

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm lint
pnpm build
```

Licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE.md).
