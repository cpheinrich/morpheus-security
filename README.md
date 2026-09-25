<p align="center">
  <img src="assets/morpheus-security-badge.png" width="180" alt="Morpheus Security badge">
</p>

# Morpheus Security

Deterministic OSV and GitHub advisory remediation for GitHub repositories. A nightly GitHub Action
in a private operations repository discovers approved repositories that installed the App and committed its policy file, opens one
dependency-only pull request at a time per lockfile, and merges only on a later run after the
repository's explicitly named checks pass.

Morpheus Security uses no model, OpenAI API, local agent, or paid service.

## Trust model

The public-but-unlisted `morpheus-security` GitHub App uses this public repository as its reviewed
source. Its schedule, sole private key, workflow logs, and scan receipts live in a separate private
operations repository. Installers grant the App access only to repositories they select and opt each repository
in by committing `.github/morpheus-security.json`. They never receive the App private key. The
maintainers retain that key in one private repository and can mint short-lived tokens for
every installation, as is normal for a centrally operated GitHub App.

Operators who do not want to trust the maintainers with that authority can fork this repository,
register their own GitHub App, and keep their key in their own private operations repository.

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
