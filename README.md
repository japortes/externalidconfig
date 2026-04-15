# externalidconfig

Exports Microsoft Entra External ID / External Identities configuration to a JSON file for assessment and review.

## What this script exports
The included PowerShell script (`export-eidconfig.ps1`) connects to Microsoft Graph and exports a structured snapshot of:

- Tenant organization details
- Domains
- Default authorization policy (including external collaboration settings)
- Cross-tenant access policy (default + partners, if present)
- Organizational branding + branding localizations
- Configured identity providers
- Custom authentication extensions
- Authentication event listeners
- External ID authentication event flows (self-service sign-up flows)
  - Flow details
  - Identity providers assigned to each flow
  - Attributes collected by each flow
- Conditional Access policies and named locations
- Authentication methods policy (per-method enablement and configuration)
- Security defaults enforcement policy
- Permission grant policies (OAuth2 consent policy overrides)
- Directory roles and per-role member enumeration

Optional sections:
- **Application inventory** (enable with `-IncludeApplications`)
  - App registrations + service principals (with credential metadata only)
  - OAuth2 delegated permission grants
  - Service-principal app-role assignments
- **Beta trust framework policies** (enable with `-IncludeBetaTrustFrameworkPolicies`)
  - Trust framework policies
  - Trust framework keysets metadata

## Prerequisites
- PowerShell 5.1+ or PowerShell 7+
- Microsoft Graph PowerShell SDK (at least the Authentication module). If missing, install:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

## Permissions (Microsoft Graph scopes)
When you run the script, it requests the following delegated scopes:
- `Organization.Read.All`
- `Domain.Read.All`
- `Policy.Read.All`
- `IdentityProvider.Read.All`
- `IdentityUserFlow.Read.All`
- `CustomAuthenticationExtension.Read.All`
- `Application.Read.All`
- `Directory.Read.All`

> Note: Some sections may return empty results or access denied depending on tenant type, permissions, or feature usage.

## Usage
Basic export:

```powershell
.\export-eidconfig.ps1
```

Specify output path:

```powershell
.\export-eidconfig.ps1 -OutputPath .\Entra-ExternalId-Assessment-Export.json
```

Include application inventory:

```powershell
.\export-eidconfig.ps1 -IncludeApplications
```

Include beta trust framework policies (IEF/custom policy scenarios):

```powershell
.\export-eidconfig.ps1 -IncludeBetaTrustFrameworkPolicies
```

Use Microsoft Graph beta for supported calls (otherwise `v1.0` is used):

```powershell
.\export-eidconfig.ps1 -UseBetaForSupportedCalls
```

## Output
The script writes a JSON document containing:
- `metadata` (timestamp, tenant/account context, flags you enabled)
- `summary` (counts/presence checks per section)
- `data` (the exported objects)

Default output file name:
- `Entra-ExternalId-Assessment-Export.json`

## Notes / safety
- This is intended for **assessment/export**, not backup/restore.
- Secrets are not exported (no client secrets, no certificate private keys).
- Throttled requests (HTTP 429) are retried automatically (up to 5 times).
