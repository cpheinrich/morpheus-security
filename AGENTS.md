# Morpheus Security agent guide

Morpheus Security is a deterministic dependency-remediation utility. Read
[`docs/policy.md`](docs/policy.md) before changing the trust boundary, App permissions, advisory
inputs, update selection, or merge behavior.

## Required checks

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm lint
pnpm build
```

Work on a branch, add tests for behavior changes, and merge through a pull request after an
independent review. Never commit a GitHub App private key. Commits created for Chris must include:

```text
Co-authored-by: Codex <codex@cpheinrich.com>
```

The public repository distributes source code, policy, and a reusable workflow. It does not offer
a hosted service. Outside operators register their own GitHub App and retain their own private key.
