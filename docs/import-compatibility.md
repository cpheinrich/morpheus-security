# Import-only compatibility lane (draft design)

This lane is **disabled by default**. Parsing `importOnlyCompatibility: true` does not by itself
authorize or run source updates. The runner and independent reviewer must both be deployed before a
repository can use it.

## Candidate boundary

A reviewed engine mapping names one advisory, the vulnerable package, one replacement registry
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

## Independent review and merge

The Security App creates and attests a candidate at one exact commit, then stops. For Morpheus's
opt-in only, a separate Manager session would review that candidate using a read-only target token.
Its apply job would recheck the Security App's attestation, diff and live head before posting a
Manager App-owned review result bound to that head. The Manager may neither push nor merge this
lane. The Security reconciler would merge only after checking that distinct review result, the
same candidate head, current holds, all configured checks, and branch protection. A changed head
or substantive finding requires a new candidate and review. No PR text, label or author-supplied
record is provenance.

This design needs the candidate builder, review-only Manager lane, PR-check verifier and pinned
private-caller rollout before activation. Until then the existing dependency-only behavior remains
the only executable automatic merge path.
