<#
.SYNOPSIS
Exports Microsoft Entra External ID / External Identities configuration to a JSON file
for assessment and review.

.DESCRIPTION
This script connects to Microsoft Graph and exports a structured snapshot of:
- Tenant organization details
- Domains
- Default authorization policy
- External collaboration settings (authorization policy)
- Cross-tenant access policy (default + partners, if present)
- Organizational branding + branding localizations
- Configured identity providers
- Custom authentication extensions
- Authentication event listeners
- External ID authentication event flows (self-service signup flows)
  - Flow details
  - Identity providers assigned to each flow
  - Attributes collected by each flow
- Optional application inventory (app registrations + service principals)
- Optional beta trust framework policies (legacy/custom policy scenarios)

.NOTES
- This script is meant for assessment/export, not backup/restore.
- It does not export secrets such as client secrets or certificates private keys.
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

    try {
        if ($Paged) {
            $items = New-Object System.Collections.Generic.List[object]
            $next = $requestUri
            while ($next) {
                $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
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
            return Invoke-MgGraphRequest -Method GET -Uri $requestUri -OutputType PSObject
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
        Invoke-GraphGet -Uri "/organization" -Paged -ApiVersion "v1.0" | Select-CleanObject
    }

    domains = Get-SafeSection -Name "domains" -ScriptBlock {
        Invoke-GraphGet -Uri "/domains" -Paged -ApiVersion "v1.0" | Select-CleanObject
    }

    authorizationPolicy = Get-SafeSection -Name "authorizationPolicy" -ScriptBlock {
        $policies = Invoke-GraphGet -Uri "/policies/authorizationPolicy" -ApiVersion "v1.0"
        $policies | Select-CleanObject
    }

    crossTenantAccess = Get-SafeSection -Name "crossTenantAccess" -ScriptBlock {
        [pscustomobject]@{
            defaultPolicy = Invoke-GraphGet -Uri "/policies/crossTenantAccessPolicy/default" -ApiVersion "v1.0" | Select-CleanObject
            partners      = Invoke-GraphGet -Uri "/policies/crossTenantAccessPolicy/partners" -Paged -ApiVersion "v1.0" | Select-CleanObject
        }
    }

    branding = Get-SafeSection -Name "branding" -ScriptBlock {
        [pscustomobject]@{
            default       = Invoke-GraphGet -Uri "/organization/$($graphContext.TenantId)/branding" -ApiVersion "v1.0" | Select-CleanObject
            localizations = Invoke-GraphGet -Uri "/organization/$($graphContext.TenantId)/branding/localizations" -Paged -ApiVersion "v1.0" | Select-CleanObject
        }
    }

    identityProviders = Get-SafeSection -Name "identityProviders" -ScriptBlock {
        Invoke-GraphGet -Uri "/identity/identityProviders" -Paged -ApiVersion "v1.0" | Select-CleanObject
    }

    customAuthenticationExtensions = Get-SafeSection -Name "customAuthenticationExtensions" -ScriptBlock {
        Invoke-GraphGet -Uri "/identity/customAuthenticationExtensions" -Paged -ApiVersion "v1.0" | Select-CleanObject
    }

    authenticationEventListeners = Get-SafeSection -Name "authenticationEventListeners" -ScriptBlock {
        Invoke-GraphGet -Uri "/identity/authenticationEventListeners" -Paged -ApiVersion "v1.0" | Select-CleanObject
    }

    authenticationEventsFlows = Get-SafeSection -Name "authenticationEventsFlows" -ScriptBlock {
        $flows = Invoke-GraphGet -Uri "/identity/authenticationEventsFlows" -Paged -ApiVersion "v1.0"
        $flowExports = @()

        foreach ($flow in $flows) {
            $flowExports += Get-FlowDetails -Flow $flow -ApiVersion "v1.0"
        }

        $flowExports | Select-CleanObject
    }
}

if ($IncludeApplications) {
    $export["applications"] = Get-SafeSection -Name "applications" -ScriptBlock {
        [pscustomobject]@{
            appRegistrations = Invoke-GraphGet -Uri "/applications" -Paged -ApiVersion "v1.0" | Select-CleanObject
            servicePrincipals = Invoke-GraphGet -Uri "/servicePrincipals" -Paged -ApiVersion "v1.0" | Select-CleanObject
        }
    }
}

if ($IncludeBetaTrustFrameworkPolicies) {
    $export["betaTrustFrameworkPolicies"] = Get-SafeSection -Name "betaTrustFrameworkPolicies" -ScriptBlock {
        Invoke-GraphGet -Uri "/trustFramework/policies" -Paged -ApiVersion "beta" | Select-CleanObject
    }
}

# Add a light summary block to make assessment easier
$summary = [ordered]@{
    organizationCount = @($export.organization).Count
    domainCount = @($export.domains).Count
    identityProviderCount = @($export.identityProviders).Count
    customAuthenticationExtensionCount = @($export.customAuthenticationExtensions).Count
    authenticationEventListenerCount = @($export.authenticationEventListeners).Count
    authenticationEventsFlowCount = @($export.authenticationEventsFlows).Count
    applicationCount = if ($IncludeApplications -and $export.applications.appRegistrations) { @($export.applications.appRegistrations).Count } else { $null }
    servicePrincipalCount = if ($IncludeApplications -and $export.applications.servicePrincipals) { @($export.applications.servicePrincipals).Count } else { $null }
    trustFrameworkPolicyCount = if ($IncludeBetaTrustFrameworkPolicies -and $export.betaTrustFrameworkPolicies) { @($export.betaTrustFrameworkPolicies).Count } else { $null }
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
