<#
.SYNOPSIS
Exports Microsoft Entra External ID / External Identities configuration to a JSON file
for assessment and review.

.DESCRIPTION
This script connects to Microsoft Graph and exports a structured snapshot of:
- Tenant organization details
- Domains
- Default authorization policy (including external collaboration settings)
- Cross-tenant access policy (default + partners, if present)
- Organizational branding + branding localizations
- Configured identity providers
- Custom authentication extensions
- Authentication event listeners
- External ID authentication event flows (self-service signup flows)
  - Flow details
  - Identity providers assigned to each flow
  - Attributes collected by each flow
- Conditional Access policies and named locations
- Authentication methods policy (per-method enablement and configuration)
- Security defaults enforcement policy
- Permission grant policies (OAuth2 consent policy overrides)
- Directory roles and per-role member enumeration
- Optional application inventory:
  - App registrations + service principals (with credential metadata)
  - OAuth2 delegated permission grants
  - Service-principal app-role assignments
- Optional beta trust framework policies (custom policy / IEF scenarios)
  - Trust framework keysets metadata

.NOTES
- This script is meant for assessment/export, not backup/restore.
- It does not export secrets such as client secrets or certificate private keys.
- Throttled requests (HTTP 429) are automatically retried up to 5 times.
- Some sections may return empty or access denied depending on tenant type, permissions, or feature usage.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Entra-ExternalId-Assessment-Export.json",

    [Parameter(Mandatory = $false)]
    [switch]$IncludeApplications,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeBetaTrustFrameworkPolicies,

    [Parameter(Mandatory = $false)]
    [switch]$UseBetaForSupportedCalls
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")]
        [string]$Level = "INFO"
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] [$Level] $Message"
}

function Ensure-GraphModule {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft Graph PowerShell SDK is not installed. Install-Module Microsoft.Graph -Scope CurrentUser"
    }
}

function Connect-AssessmentGraph {
    $scopes = @(
        "Organization.Read.All",
        "Domain.Read.All",
        "Policy.Read.All",
        "IdentityProvider.Read.All",
        "IdentityUserFlow.Read.All",
        "CustomAuthenticationExtension.Read.All",
        "Application.Read.All",
        "Directory.Read.All"
    )

    try {
        Write-Log "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
        $ctx = Get-MgContext
        if (-not $ctx) {
            throw "Graph context was not established."
        }
        Write-Log "Connected to Microsoft Graph tenant: $($ctx.TenantId)"
        return $ctx
    }
    catch {
        throw "Failed to connect to Microsoft Graph. $($_.Exception.Message)"
    }
}

function Invoke-GraphGet {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $false)][switch]$Paged,
        [Parameter(Mandatory = $false)][string]$ApiVersion = "v1.0"
    )

    $baseUri = "https://graph.microsoft.com/$ApiVersion"
    $requestUri = if ($Uri -match '^https://') { $Uri } else { "$baseUri$Uri" }

    $maxRetries = 5

    function Invoke-WithRetry {
        param([string]$TargetUri)
        $attempt = 0
        while ($true) {
            try {
                return Invoke-MgGraphRequest -Method GET -Uri $TargetUri -OutputType PSObject
            }
            catch {
                $msg = $_.Exception.Message
                $attempt++
                # Retry on throttling (429) or transient gateway errors (503/504)
                if ($attempt -le $maxRetries -and ($msg -match "429|TooManyRequests|503|504|ServiceUnavailable|GatewayTimeout")) {
                    # Honor Retry-After if present in the message; only accept numeric (seconds) values in a sane range
                    $wait = 0
                    if ($msg -match 'Retry-After[:\s]+(\d+)') {
                        $parsed = [int]$Matches[1]
                        $wait = if ($parsed -gt 0 -and $parsed -le 300) { $parsed } else { 0 }
                    }
                    if ($wait -eq 0) { $wait = [math]::Pow(2, $attempt) * 5 }
                    Write-Log "Throttled/transient error on $TargetUri. Waiting $wait s (attempt $attempt/$maxRetries)..." "WARN"
                    Start-Sleep -Seconds $wait
                }
                else {
                    throw
                }
            }
        }
    }

    try {
        if ($Paged) {
            $items = New-Object System.Collections.Generic.List[object]
            $next = $requestUri
            while ($next) {
                $resp = Invoke-WithRetry -TargetUri $next
                if ($null -ne $resp.value) {
                    foreach ($item in $resp.value) { $items.Add($item) }
                }
                elseif ($null -ne $resp) {
                    $items.Add($resp)
                }
                $next = $resp.'@odata.nextLink'
            }
            return $items
        }
        else {
            return Invoke-WithRetry -TargetUri $requestUri
        }
    }
    catch {
        Write-Log "GET failed: $requestUri -- $($_.Exception.Message)" "WARN"
        return [pscustomobject]@{
            _error = $true
            message = $_.Exception.Message
            uri = $requestUri
        }
    }
}

function Get-SafeSection {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock
    )

    try {
        Write-Log "Exporting section: $Name"
        return & $ScriptBlock
    }
    catch {
        Write-Log "Section failed: $Name -- $($_.Exception.Message)" "WARN"
        return [pscustomobject]@{
            _section = $Name
            _error   = $true
            message  = $_.Exception.Message
        }
    }
}

function Select-CleanObject {
    param([Parameter(ValueFromPipeline = $true)]$InputObject)
    process {
        if ($null -eq $InputObject) { return $null }
        return ($InputObject | ConvertTo-Json -Depth 50 | ConvertFrom-Json)
    }
}

# Returns a count for summary; returns "error" when the section itself failed.
function Get-SafeCount {
    param($Collection)
    if ($null -eq $Collection) { return 0 }
    $arr = @($Collection)
    if ($arr.Count -eq 1 -and ($arr[0].PSObject.Properties.Name -contains '_error') -and $arr[0]._error -eq $true) {
        return "error"
    }
    return $arr.Count
}

# Returns $true when a section object represents a successful (non-error) result.
function Test-SectionOk {
    param($Section)
    if ($null -eq $Section) { return $false }
    return -not (($Section.PSObject.Properties.Name -contains '_error') -and $Section._error -eq $true)
}

function Get-FlowDetails {
    param(
        [Parameter(Mandatory = $true)]$Flow,
        [Parameter(Mandatory = $false)][string]$ApiVersion = "v1.0"
    )

    $flowId = $Flow.id
    $details = [ordered]@{
        flow = $Flow | Select-CleanObject
        identityProviders = $null
        attributes = $null
    }

    # Identity providers attached to this self-service sign-up flow
    $details.identityProviders = Invoke-GraphGet `
        -Uri "/identity/authenticationEventsFlows/$flowId/microsoft.graph.externalUsersSelfServiceSignupEventsFlow/onAuthenticationMethodLoadStart/identityProviders" `
        -Paged `
        -ApiVersion $ApiVersion | Select-CleanObject

    # Attributes collected by this self-service sign-up flow
    $details.attributes = Invoke-GraphGet `
        -Uri "/identity/authenticationEventsFlows/$flowId/microsoft.graph.externalUsersSelfServiceSignupEventsFlow/onAttributeCollection/attributes" `
        -Paged `
        -ApiVersion $ApiVersion | Select-CleanObject

    return [pscustomobject]$details
}

Ensure-GraphModule
$graphContext = Connect-AssessmentGraph

$profileInfo = [ordered]@{
    timestampUtc   = (Get-Date).ToUniversalTime().ToString("o")
    tenantId       = $graphContext.TenantId
    account        = $graphContext.Account
    environment    = $graphContext.Environment
    includeApplications = [bool]$IncludeApplications
    includeBetaTrustFrameworkPolicies = [bool]$IncludeBetaTrustFrameworkPolicies
    useBetaForSupportedCalls = [bool]$UseBetaForSupportedCalls
}

$apiVersion = if ($UseBetaForSupportedCalls) { "beta" } else { "v1.0" }

$export = [ordered]@{
    metadata = $profileInfo

    organization = Get-SafeSection -Name "organization" -ScriptBlock {
        Invoke-GraphGet -Uri "/organization" -Paged -ApiVersion $apiVersion | Select-CleanObject
    }

    domains = Get-SafeSection -Name "domains" -ScriptBlock {
        Invoke-GraphGet -Uri "/domains" -Paged -ApiVersion $apiVersion | Select-CleanObject
    }

    authorizationPolicy = Get-SafeSection -Name "authorizationPolicy" -ScriptBlock {
        Invoke-GraphGet -Uri "/policies/authorizationPolicy" -ApiVersion $apiVersion | Select-CleanObject
    }

    crossTenantAccess = Get-SafeSection -Name "crossTenantAccess" -ScriptBlock {
        [pscustomobject]@{
            defaultPolicy = Invoke-GraphGet -Uri "/policies/crossTenantAccessPolicy/default" -ApiVersion $apiVersion | Select-CleanObject
            partners      = Invoke-GraphGet -Uri "/policies/crossTenantAccessPolicy/partners" -Paged -ApiVersion $apiVersion | Select-CleanObject
        }
    }

    branding = Get-SafeSection -Name "branding" -ScriptBlock {
        [pscustomobject]@{
            default       = Invoke-GraphGet -Uri "/organization/$($graphContext.TenantId)/branding" -ApiVersion $apiVersion | Select-CleanObject
            localizations = Invoke-GraphGet -Uri "/organization/$($graphContext.TenantId)/branding/localizations" -Paged -ApiVersion $apiVersion | Select-CleanObject
        }
    }

    identityProviders = Get-SafeSection -Name "identityProviders" -ScriptBlock {
        Invoke-GraphGet -Uri "/identity/identityProviders" -Paged -ApiVersion $apiVersion | Select-CleanObject
    }

    customAuthenticationExtensions = Get-SafeSection -Name "customAuthenticationExtensions" -ScriptBlock {
        Invoke-GraphGet -Uri "/identity/customAuthenticationExtensions" -Paged -ApiVersion $apiVersion | Select-CleanObject
    }

    authenticationEventListeners = Get-SafeSection -Name "authenticationEventListeners" -ScriptBlock {
        Invoke-GraphGet -Uri "/identity/authenticationEventListeners" -Paged -ApiVersion $apiVersion | Select-CleanObject
    }

    authenticationEventsFlows = Get-SafeSection -Name "authenticationEventsFlows" -ScriptBlock {
        $flows = Invoke-GraphGet -Uri "/identity/authenticationEventsFlows" -Paged -ApiVersion $apiVersion
        $flowExports = @()
        foreach ($flow in $flows) {
            $flowExports += Get-FlowDetails -Flow $flow -ApiVersion $apiVersion
        }
        $flowExports | Select-CleanObject
    }

    # -----------------------------------------------------------------------
    # Conditional Access
    # -----------------------------------------------------------------------
    conditionalAccess = Get-SafeSection -Name "conditionalAccess" -ScriptBlock {
        [pscustomobject]@{
            policies       = Invoke-GraphGet -Uri "/identity/conditionalAccess/policies" -Paged -ApiVersion $apiVersion | Select-CleanObject
            namedLocations = Invoke-GraphGet -Uri "/identity/conditionalAccess/namedLocations" -Paged -ApiVersion $apiVersion | Select-CleanObject
        }
    }

    # -----------------------------------------------------------------------
    # Authentication methods policy
    # Captures per-method enablement, target groups, and FIDO2/passkey settings.
    # -----------------------------------------------------------------------
    authenticationMethodsPolicy = Get-SafeSection -Name "authenticationMethodsPolicy" -ScriptBlock {
        Invoke-GraphGet -Uri "/policies/authenticationMethodsPolicy" -ApiVersion $apiVersion | Select-CleanObject
    }

    # -----------------------------------------------------------------------
    # Security defaults
    # -----------------------------------------------------------------------
    securityDefaults = Get-SafeSection -Name "securityDefaults" -ScriptBlock {
        Invoke-GraphGet -Uri "/policies/identitySecurityDefaultsEnforcementPolicy" -ApiVersion $apiVersion | Select-CleanObject
    }

    # -----------------------------------------------------------------------
    # OAuth2 consent / permission-grant policies
    # Shows whether custom consent policies override the built-in defaults and
    # what operations they permit (e.g. user consent to verified publishers).
    # -----------------------------------------------------------------------
    permissionGrantPolicies = Get-SafeSection -Name "permissionGrantPolicies" -ScriptBlock {
        Invoke-GraphGet -Uri "/policies/permissionGrantPolicies" -Paged -ApiVersion $apiVersion | Select-CleanObject
    }

    # -----------------------------------------------------------------------
    # Directory roles and their current members
    # Covers built-in and custom roles; per-role member list surfaces
    # who can modify External ID controls or tenant configuration.
    # -----------------------------------------------------------------------
    directoryRoles = Get-SafeSection -Name "directoryRoles" -ScriptBlock {
        $roles = Invoke-GraphGet -Uri "/directoryRoles" -Paged -ApiVersion $apiVersion
        $roleExports = @()
        foreach ($role in $roles) {
            $members = Invoke-GraphGet -Uri "/directoryRoles/$($role.id)/members" -Paged -ApiVersion $apiVersion | Select-CleanObject
            $roleExports += [pscustomobject]@{
                role    = $role | Select-CleanObject
                members = $members
            }
        }
        $roleExports
    }
}

if ($IncludeApplications) {
    $export["applications"] = Get-SafeSection -Name "applications" -ScriptBlock {
        # Fetch app registrations and service principals
        $appRegs = Invoke-GraphGet -Uri "/applications" -Paged -ApiVersion $apiVersion | Select-CleanObject
        $sps     = Invoke-GraphGet -Uri "/servicePrincipals" -Paged -ApiVersion $apiVersion | Select-CleanObject

        # Delegated permission grants (OAuth2): who consented to what on behalf of whom
        $oauth2Grants = Invoke-GraphGet -Uri "/oauth2PermissionGrants" -Paged -ApiVersion $apiVersion | Select-CleanObject

        # App-role assignments granted to service principals (application permissions)
        # Enumerate per service-principal to capture the full picture
        $spAppRoleAssignments = @()
        foreach ($sp in @($sps)) {
            if ($null -eq $sp -or (($sp.PSObject.Properties.Name -contains '_error') -and $sp._error -eq $true)) { continue }
            $assignments = Invoke-GraphGet -Uri "/servicePrincipals/$($sp.id)/appRoleAssignments" -Paged -ApiVersion $apiVersion | Select-CleanObject
            if ($assignments) {
                $spAppRoleAssignments += $assignments
            }
        }

        [pscustomobject]@{
            appRegistrations       = $appRegs
            servicePrincipals      = $sps
            oauth2PermissionGrants = $oauth2Grants
            appRoleAssignments     = $spAppRoleAssignments
        }
    }
}

if ($IncludeBetaTrustFrameworkPolicies) {
    $export["betaTrustFrameworkPolicies"] = Get-SafeSection -Name "betaTrustFrameworkPolicies" -ScriptBlock {
        [pscustomobject]@{
            # Custom policies (IEF / XML) — content is XML text, useful for full IEF audits
            policies = Invoke-GraphGet -Uri "/trustFramework/policies" -Paged -ApiVersion "beta" | Select-CleanObject
            # Keysets: certificate/key material metadata used by custom policies (no private key material returned)
            keySets  = Invoke-GraphGet -Uri "/trustFramework/keySets" -Paged -ApiVersion "beta" | Select-CleanObject
        }
    }
}

# Add a light summary block to make assessment easier
$summary = [ordered]@{
    organizationCount                    = Get-SafeCount $export.organization
    domainCount                          = Get-SafeCount $export.domains
    identityProviderCount                = Get-SafeCount $export.identityProviders
    customAuthenticationExtensionCount   = Get-SafeCount $export.customAuthenticationExtensions
    authenticationEventListenerCount     = Get-SafeCount $export.authenticationEventListeners
    authenticationEventsFlowCount        = Get-SafeCount $export.authenticationEventsFlows
    conditionalAccessPolicyCount         = if (Test-SectionOk $export.conditionalAccess) { Get-SafeCount $export.conditionalAccess.policies } else { "error" }
    namedLocationCount                   = if (Test-SectionOk $export.conditionalAccess) { Get-SafeCount $export.conditionalAccess.namedLocations } else { "error" }
    authMethodsPolicyPresent             = if (Test-SectionOk $export.authenticationMethodsPolicy) { $true } else { $false }
    securityDefaultsEnabled              = if ((Test-SectionOk $export.securityDefaults) -and $null -ne $export.securityDefaults.isEnabled) { $export.securityDefaults.isEnabled } else { "error" }
    permissionGrantPolicyCount           = Get-SafeCount $export.permissionGrantPolicies
    directoryRoleCount                   = Get-SafeCount $export.directoryRoles
    applicationCount                     = if ($IncludeApplications -and (Test-SectionOk $export.applications)) { Get-SafeCount $export.applications.appRegistrations } else { $null }
    servicePrincipalCount                = if ($IncludeApplications -and (Test-SectionOk $export.applications)) { Get-SafeCount $export.applications.servicePrincipals } else { $null }
    oauth2PermissionGrantCount           = if ($IncludeApplications -and (Test-SectionOk $export.applications)) { Get-SafeCount $export.applications.oauth2PermissionGrants } else { $null }
    appRoleAssignmentCount               = if ($IncludeApplications -and (Test-SectionOk $export.applications)) { Get-SafeCount $export.applications.appRoleAssignments } else { $null }
    trustFrameworkPolicyCount            = if ($IncludeBetaTrustFrameworkPolicies -and (Test-SectionOk $export.betaTrustFrameworkPolicies)) { Get-SafeCount $export.betaTrustFrameworkPolicies.policies } else { $null }
    trustFrameworkKeySetCount            = if ($IncludeBetaTrustFrameworkPolicies -and (Test-SectionOk $export.betaTrustFrameworkPolicies)) { Get-SafeCount $export.betaTrustFrameworkPolicies.keySets } else { $null }
}

$final = [ordered]@{
    summary = $summary
    data    = $export
}

Write-Log "Writing JSON export to $OutputPath"
$final | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutputPath -Encoding utf8

Write-Log "Export complete."
Write-Host ""
Write-Host "Output file: $OutputPath"
Write-Host "Tenant Id  : $($graphContext.TenantId)"
Write-Host ""
Write-Host "Summary:"
$summary.GetEnumerator() | Sort-Object Name | ForEach-Object {
    Write-Host (" - {0}: {1}" -f $_.Key, $_.Value)
}
