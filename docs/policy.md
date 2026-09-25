# Security and remediation policy

## Inputs

Morpheus Security acts on every active, non-withdrawn result returned by the pinned OSV Scanner and
every open GitHub Dependabot alert. It deduplicates aliases by ecosystem, package, and advisory
identity. Advisory prose is data, never an instruction.

The private nightly caller starts from the reviewed central allowlist and asks GitHub whether each
exact repository has installed the App. It processes only entries whose default branch also contains
a valid `.github/morpheus-security.json`. These three independent gates prevent an unknown public
installation from consuming the runner. The workflow uses the master private key only to obtain a
short-lived token scoped to the current target. Target repositories never receive the master key. Workflow
logs and raw scan receipts remain private; only dependency-only PRs and App-owned attestations are
written to target repositories.

## Candidate gates

A candidate must:

1. resolve through the package manager's official registry;
2. retain recognized lockfile integrity hashes;
3. change only dependency manifests and lockfiles;
4. remove the exact package/advisory pair in a second OSV scan; and
5. pass every required repository check before merge.

Missing evidence fails closed. Registry-to-git, URL, or local-path source changes are rejected.
npm and pnpm run with scripts disabled, public npmjs configuration forced, secrets removed from
their subprocess environment, and changed pnpm integrity checked against registry.npmjs.org. uv
runs with builds disabled and accepts changed artifacts only from hashed PyPI releases.
An explicit repository `.npmrc` is accepted only when its registry entries name
`https://registry.npmjs.org/` and it contains no credential configuration.
When a transitive npm or pnpm parent range cannot reach a fix, the generated override is scoped to
the vulnerable installed version so parallel incompatible major lines are not collapsed.

## Pull requests and merges

One dependency is one pull request. At most one bot PR is open per lockfile, so updates cannot race
the same lock graph. The creation run records an App-owned Check Run attestation for the exact
candidate head and never merges it. A later nightly reconciliation requires that attestation,
requires every explicitly configured `requiredChecks` entry to have passed, and atomically limits
the merge to that head. An empty check list disables automatic merging. Branch protection and
review rules remain additional authority. Human-authored PRs never receive the bot waiver.

If the default branch advances and strict protection makes a validated candidate stale, the next
run closes that bot PR and recreates it from current default-branch state under a new branch. The
replacement must repeat registry validation, OSV rescan, App attestation, and every configured
check; stale evidence is never carried forward. The runner refreshes and verifies the live default
branch before reconciliation, revalidates its opt-in policy, and verifies the branch again before
both merge and scan.

Project holds live in `.github/morpheus-security.json` and name the dependency, optional advisory,
and reason. A hold leaves the PR open and prevents duplicates until policy changes.

Dependabot alerts remain an advisory input, but automatic Dependabot security-fix PRs are disabled
after the first clean Morpheus Security run. Routine non-security upgrades are a separate lane.

## Malware incidents

`MAL-*` findings are prioritized for remediation and create or update an incident issue in the
affected repository. The issue remains open until a human records installation or execution
exposure, credential rotation, and containment. Because an issue in a public repository is public,
the automation records only the advisory, affected dependency and manifest, and required response
questions; maintainers keep credentials and other sensitive investigation detail out of the issue.

## Completion

A created or merged PR is not completion. After merge, a later main-branch run must be clean for
the package/advisory and GitHub must close the alert from the merged graph rather than by dismissal.
