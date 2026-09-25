# Installation

Morpheus Security is self-hosted inside GitHub Actions. Register a GitHub App under the account that
owns the target repositories. If one App must span unrelated accounts, its registration must be
public; it does not need to be listed in GitHub Marketplace.

## GitHub App permissions

| Repository permission | Access |
|---|---|
| Metadata | Read |
| Actions | Read |
| Checks | Read |
| Commit statuses | Read |
| Dependabot alerts | Read |
| Contents | Read and write |
| Issues | Read and write |
| Pull requests | Read and write |

Grant no organization or account permissions. Leave OAuth user authorization, Device Flow, and
webhooks disabled.

Generate a private key and store these encrypted repository secrets:

- `MORPHEUS_SECURITY_APP_ID`
- `MORPHEUS_SECURITY_PRIVATE_KEY`

Delete the downloaded key after the secret is verified. Never commit or distribute it.

The private key proves the App's identity. Its holder can exchange a signed JWT for one-hour tokens
covering any installation and repository permissions granted to the App. A compromised key can
therefore affect every installation; rotate it immediately if exposure is suspected.

## Repository policy

Create `.github/morpheus-security.json`:

```json
{
  "version": 1,
  "holds": [],
  "incidentRepository": null
}
```

For a public repository, set `incidentRepository` to a private repository owned by the same App
installation and include that repository when installing the App.

## Caller

Pin both the reusable workflow and `security-sha` to the same reviewed commit:

```yaml
name: Security remediation

on:
  schedule:
    - cron: "43 10 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  remediate:
    uses: cpheinrich/morpheus-security/.github/workflows/security-remediation.yml@<reviewed-sha>
    with:
      security-sha: <reviewed-sha>
      config-file: .github/morpheus-security.json
    secrets:
      app_id: ${{ secrets.MORPHEUS_SECURITY_APP_ID }}
      app_private_key: ${{ secrets.MORPHEUS_SECURITY_PRIVATE_KEY }}
```

Dispatch once manually. Follow each bot PR through required checks and auto-merge, then dispatch
again until the main-branch receipt is clean and the corresponding GitHub alert closes. Only then
disable Dependabot automatic security-fix PRs; keep Dependabot alerts enabled.
