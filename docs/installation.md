# Installation

Morpheus Security is a centrally operated, public-but-unlisted GitHub App. Its nightly workflow
runs from this repository; installers do not receive or configure the App private key.

## GitHub App permissions

| Repository permission | Access |
|---|---|
| Metadata | Read |
| Checks | Read and write |
| Commit statuses | Read |
| Dependabot alerts | Read |
| Contents | Read and write |
| Issues | Read and write |
| Pull requests | Read and write |

The App has no organization or account permissions. OAuth user authorization, Device Flow,
webhooks, and Actions access are disabled.

## Install and opt in

1. Install `morpheus-security` on **only select repositories**. An installation grants the App
   access but does not provide its private key to the installer.
2. Ask a maintainer to add the exact `owner/name` to `config/approved-repositories.json`. This
   reviewed allowlist prevents an unknown public installation from consuming or attacking the
   central runner.
3. Commit `.github/morpheus-security.json` to each repository that should run nightly:

```json
{
  "version": 1,
  "holds": [],
  "requiredChecks": ["test"],
  "incidentRepository": null
}
```

Installation alone is inert. The central workflow processes a repository only when the App is
installed, the central allowlist approves it, and its default branch contains this valid policy
file. Removing the policy file opts the repository out without changing the installation.

`requiredChecks` is the explicit automatic-merge allowlist. Use exact GitHub check names. An empty
list permits scans and PR creation but disables automatic merging. Branch protection and review
rules remain additional GitHub-enforced gates.

For a public repository, create a private incident repository under the same owner, include it in
the App installation, and set `incidentRepository` to its `owner/name`. This prevents malware
exposure details from being published in a public issue.

The next nightly run picks up the repository. A new PR is never merged in its creation run. The App
records a Check Run attestation for the exact validated head; a later run requires that attestation
and all configured checks before atomically merging that head. A further run must confirm that the
main-branch graph is clean and GitHub has closed the alert. Only then disable Dependabot automatic
security-fix PRs; keep Dependabot alerts enabled.

## Credential custody and self-hosting

The maintainers keep the App private key only in the protected `security-bot` environment of this
repository, with an offline recovery copy in a credential vault. GitHub stores only the public
portion. The central workflow exchanges the key for short-lived, least-privilege tokens scoped to
one target repository and its optional incident repository, then revokes its discovery tokens.

The private key grants authority across every installation. Install only if you trust the App's
maintainers and reviewed workflow with the selected repositories. To retain that authority
yourself, fork this repository, register a separate GitHub App with the permissions above, and
store your own App ID and private key once in a protected `security-bot` environment as:

- `MORPHEUS_SECURITY_APP_ID`
- `MORPHEUS_SECURITY_PRIVATE_KEY`

Never commit or distribute the private key. Require pull-request review and passing CI for changes
to the orchestrator workflow and scripts. Rotate the key immediately if exposure is suspected.
