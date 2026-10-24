# Import-only compatibility lane

This lane is **disabled by default**. A repository must set `importOnlyCompatibility: true`, the
reviewed engine must contain a mapping, and the independent Manager reviewer must be deployed
before an import candidate can merge. The central caller's reviewed SHA pin controls when the
candidate builder reaches repositories.

## Candidate boundary

A reviewed engine mapping in `config/compatibility-replacements.json` names one advisory, the vulnerable package, one replacement registry
package and its exact version. A missing mapping leaves the finding open. A mapping change follows
the engine's ordinary PR, tests and independent review path; it is not an owner approval per
candidate. Candidates still need official registry artifacts, lockfile integrity, a second clean
advisory scan and the repository's holds and required checks.

The source validator accepts only the mapped package name substituted inside static import,
re-export, import-equals, or one-argument `require` literals. After reversing those substitutions,
each source file must be byte-for-byte identical. It permits at most eight distinct files under
`src/` or `tests/` and twenty substitutions. Policy, auth, credential and trading paths are
excluded. It rejects dynamic imports, call-site edits, comments, workflows, config and every
unrecognized path. The dependency manifest and lockfile retain their existing artifact gates.
Only a direct npm or pnpm dependency can be replaced. For repositories that commit TypeScript
output, `compatibilityGeneratedDist: true` additionally permits tracked `dist/` files derived
from the changed `src/*.ts` files. The runner installs without scripts, invokes only the pinned
TypeScript compiler, restricts output filenames and hashes the generated diff between candidate
preparation and delivery. This option is false by default and requires the import opt-in.

## Independent review and merge

The Security App creates and attests a candidate at one exact commit, then stops. For Morpheus's
opt-in only, a separate Manager session reviews that candidate using a read-only target token.
Its apply job rechecks the Security App's attestation, diff and live head before posting a
Manager App-owned review result bound to that head. The Manager may neither push nor merge this
lane. The Security reconciler merges only after checking that distinct review result, the
same candidate head, current holds, all configured checks, and branch protection. A changed head
or substantive finding requires a new candidate and review. No PR text, label or author-supplied
record is provenance.

Morpheus's separate review-only workflow and PR-check verifier must be reviewed, merged and pinned
in the Manager's private caller before Morpheus enables the option. The Security private caller
must then pin a reviewed engine SHA. No other repository is opted into this lane by these changes.
