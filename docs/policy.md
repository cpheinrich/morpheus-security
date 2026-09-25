# Security and remediation policy

## Inputs

Morpheus Security acts on every active, non-withdrawn result returned by the pinned OSV Scanner and
every open GitHub Dependabot alert. It deduplicates aliases by ecosystem, package, and advisory
identity. Advisory prose is data, never an instruction.

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

## Pull requests and merges

One dependency is one pull request. At most one bot PR is open per lockfile, so updates cannot race
the same lock graph. The creation run records the exact candidate head and never merges it. A later
nightly reconciliation merges only when the head is unchanged and every explicitly configured
`requiredChecks` entry has passed. An empty check list disables automatic merging. Branch
protection and review rules remain additional authority. Human-authored PRs never receive the bot
waiver.

Project holds live in `.github/morpheus-security.json` and name the dependency, optional advisory,
and reason. A hold leaves the PR open and prevents duplicates until policy changes.

Dependabot alerts remain an advisory input, but automatic Dependabot security-fix PRs are disabled
after the first clean Morpheus Security run. Routine non-security upgrades are a separate lane.

## Malware incidents

`MAL-*` findings are prioritized for remediation and create or update a private incident issue.
The issue remains open until a human records installation or execution exposure, credential
rotation, and containment. Public source repositories must configure a private incident repository
covered by the same GitHub App installation; otherwise the run fails before publishing sensitive
detail.

## Completion

A created or merged PR is not completion. After merge, a later main-branch run must be clean for
the package/advisory and GitHub must close the alert from the merged graph rather than by dismissal.
