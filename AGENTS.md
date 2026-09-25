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

The public repository is reviewed source for the public-but-unlisted App. A separate private
operations repository owns the nightly caller, master key, logs, and receipts. Installed
repositories never receive the master key. Preserve central credential custody, reviewed allowlist,
per-target tokens, incident issues in the affected repository, committed opt-in policy, and
protected-main review as one trust boundary. Self-hosting operators register their own App and
private caller.
