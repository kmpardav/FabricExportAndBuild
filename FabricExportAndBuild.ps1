#requires -Version 5.1
<#
  FabricExportAndBuild.ps1
  Author: Konstantinos Bardavouras (@kostasmadhatter)
  License: MIT

  WHAT IT DOES
  - Export (default): Dumps Workspaces, Items, RoleAssignments, Capacities, Domains to JSON
  - Build (-Build):   Reads JSON and prints readable tables in the console
  - BuildAndExtract:  Runs export and build in one go

  IMPORTANT
  - Calls Microsoft Fabric REST APIs (Core/Admin) with pagination and throttling handling.
    • Workspaces – List (Core, paged) ........................................ MS Docs :contentReference[oaicite:1]{index=1}
    • Items – List (Core, paged) ............................................. MS Docs :contentReference[oaicite:2]{index=2}
    • Workspace Role Assignments – List (Core, paged) ........................ MS Docs :contentReference[oaicite:3]{index=3}
    • Domains – List (Admin, 25 req/min) ..................................... MS Docs :contentReference[oaicite:4]{index=4}
    • Throttling 429 + Retry-After ........................................... MS Docs :contentReference[oaicite:5]{index=5}
  - Auth: OAuth2 Client Credentials (Entra ID) using scope https://api.fabric.microsoft.com/.default. :contentReference[oaicite:6]{index=6}

  SECURITY
  - Never commit TenantId/ClientId/ClientSecret. Pass them as parameters or environment variables.
  - For docs/samples, use placeholders (TENANT_ID, CLIENT_ID, CLIENT_SECRET).
#>

[CmdletBinding()]
param(
  # ---- Creds  ----
  [string]$TenantId,
  [string]$ClientId,
  [string]$ClientSecret,

  # ---- Paths ----
  [string]$OutputPath = ".\fabric-export.json",  
  [string]$InputPath,                            

  # ---- Modes ----
  [switch]$Build,            
  [switch]$BuildAndExtract,  # export + build

  # ---- Export tuning ----
  [int]$MaxRps = 3,
  [int]$MaxRetries = 8,
  [int]$BaseBackoffSec = 2,
  [switch]$IncludeAccessDetails,
  [int]$AccessGapSeconds = 20,
  [int]$AccessMaxCount = 200
)

# ---------- Helpers: Throttle + Retry with jitter ----------
$script:LastCallUtc = [DateTime]::UtcNow.AddSeconds(-10)
function Wait-IfNeeded {
  param([int]$MaxRps)
  $gap = 1.0 / [double]$MaxRps
  $elapsed = ([DateTime]::UtcNow - $script:LastCallUtc).TotalSeconds
  $remain = $gap - $elapsed
  if ($remain -gt 0) { Start-Sleep -Milliseconds ([int][math]::Ceiling(1000 * $remain)) }
  $script:LastCallUtc = [DateTime]::UtcNow
}

function Get-JitterSeconds([int]$base) {
  # +/- 20% jitter
  $rand = Get-Random -Minimum 0.8 -Maximum 1.2
  return [int]([math]::Ceiling($base * $rand))
}

function Invoke-FabricApi {
  param(
    [Parameter(Mandatory)][string]$Uri,
    [Parameter(Mandatory)][hashtable]$Headers,
    [string]$Method = 'GET',
    [int]$MaxRetries = 8,
    [int]$BaseBackoffSec = 2,
    [int]$MaxRps = 3,
    $Body = $null
  )
  $try = 0
  do {
    Wait-IfNeeded -MaxRps $MaxRps
    try {
      $methodUpper = $Method.ToUpperInvariant()
      $sendBody = ($Body -ne $null) -and @('POST','PUT','PATCH','DELETE').Contains($methodUpper)
      if ($sendBody) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers `
               -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 10) -ErrorAction Stop
      } else {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -ErrorAction Stop
      }
    } catch {
      $try++
      $resp = $_.Exception.Response
      $code = if ($resp) { $resp.StatusCode.value__ } else { 0 }
      $respBody = if ($resp) { (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } else { '' }

      $throttled = ($code -eq 429) -or ($respBody -match 'RequestBlocked')
      if (-not $throttled -and $code -ne 503 -and $code -ne 502) { throw }
      if ($try -ge $MaxRetries) { throw }

      $retryAfter = if ($resp) { $resp.Headers['Retry-After'] } else { $null }
      if ($retryAfter) {
        $wait = [int]$retryAfter
      } elseif ($respBody -match 'until:\s+([0-9\/\-\s:]+)\s*\(UTC\)') {
        $wait = [math]::Max(1, [int]([DateTime]::Parse($Matches[1]) - [DateTime]::UtcNow).TotalSeconds)
      } else {
        $wait = $BaseBackoffSec * [math]::Pow(2, $try - 1)
      }
      $wait = Get-JitterSeconds $wait
      Write-Warning ("Retry {0}/{1} (HTTP {2}) - wait {3}s" -f $try, $MaxRetries, $code, $wait)
      Start-Sleep -Seconds $wait
    }
  } while ($true)
}

function Try-Get {
  param([string]$Uri, [hashtable]$Headers, [int]$MaxRps = 3)
  try { Invoke-FabricApi -Uri $Uri -Headers $Headers -MaxRps $MaxRps }
  catch {
    $resp = $_.Exception.Response
    if ($resp -and $resp.StatusCode.value__ -eq 404) {
      Write-Warning ("Skip 404 -> {0}" -f $Uri)
      return @{ value = @() }
    }
    throw
  }
}

# ---------- Pagination helper (uses continuationToken/continuationUri) ----------
function Invoke-FabricPaged {
  param(
    [Parameter(Mandatory)][string]$BaseUri,
    [Parameter(Mandatory)][hashtable]$Headers,
    [int]$MaxRps = 3
  )
  $all = New-Object System.Collections.Generic.List[object]
  $uri = $BaseUri
  do {
    $resp = Try-Get -Uri $uri -Headers $Headers -MaxRps $MaxRps
    if ($resp.value) { $all.AddRange($resp.value) }
    $next = $null
    if ($resp.PSObject.Properties.Name -contains 'continuationUri' -and $resp.continuationUri) {
      $next = $resp.continuationUri
    } elseif ($resp.PSObject.Properties.Name -contains 'continuationToken' -and $resp.continuationToken) {
      # Fallback pattern: append ?continuationToken=...
      if ($uri -like '*?*') {
        $sep = '&'
      } else {
        $sep = '?'
      }
      $next = "$($BaseUri)$sep" + "continuationToken=$([uri]::EscapeDataString($resp.continuationToken))"
    }
    $uri = $next
  } while ($uri)
  return @($all.ToArray())
}

# ---------- Export (Core + Admin minimal) ----------
function Do-Export {
  param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [Parameter(Mandatory)][string]$OutputPath,
    [int]$MaxRps, [int]$MaxRetries, [int]$BaseBackoffSec,
    [switch]$IncludeAccessDetails, [int]$AccessGapSeconds, [int]$AccessMaxCount
  )

  Write-Host "Acquiring token ..."
  $token = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body @{
      grant_type    = "client_credentials"
      client_id     = $ClientId
      client_secret = $ClientSecret
      scope         = "https://api.fabric.microsoft.com/.default"
    }
  $auth = @{ Authorization = "Bearer $($token.access_token)" }

  Write-Host "Fetching workspaces (paged) ..."
  $wsList = Invoke-FabricPaged -BaseUri "https://api.fabric.microsoft.com/v1/workspaces" -Headers $auth -MaxRps $MaxRps  # paging (Core)

  $wsExport = @()
  foreach ($ws in $wsList) {
    Write-Host ("  - {0}" -f $ws.displayName)

    $items = Invoke-FabricPaged -BaseUri "https://api.fabric.microsoft.com/v1/workspaces/$($ws.id)/items?maxResults=10000" -Headers $auth -MaxRps $MaxRps  # paging (Core)
    $roles = Invoke-FabricPaged -BaseUri "https://api.fabric.microsoft.com/v1/workspaces/$($ws.id)/roleAssignments?maxResults=10000" -Headers $auth -MaxRps $MaxRps  # paging (Core)

    $wsExport += [PSCustomObject]@{
      Workspace       = $ws
      Items           = $items
      RoleAssignments = $roles
    }
  }

  Write-Host "Fetching capacities ..."
  $capList = Invoke-FabricApi -Uri "https://api.fabric.microsoft.com/v1/capacities" -Headers $auth -MaxRps $MaxRps -MaxRetries $MaxRetries -BaseBackoffSec $BaseBackoffSec

  $domains = @()
  try {
    Write-Host "Fetching domains (Admin, 25 req/min cap) ..."
    $domResp = Invoke-FabricApi -Uri "https://api.fabric.microsoft.com/v1/admin/domains?preview=false" -Headers $auth -MaxRps 1 -MaxRetries $MaxRetries -BaseBackoffSec $BaseBackoffSec  # 25/min
    $domains = $domResp.domains
  } catch {
    Write-Warning "Skipped domains (no Fabric-Admin perms or throttled)."
  }

  $accessDetails = @()
  if ($IncludeAccessDetails) {
    Write-Host "Fetching workspace access details (Admin, capped per hour) ..."
    $taken = 0
    foreach ($ws in $wsList) {
      if ($taken -ge $AccessMaxCount) { break }
      $uri = "https://api.fabric.microsoft.com/v1/admin/workspaces/$($ws.id)/users"
      try {
        $resp = Invoke-FabricApi -Uri $uri -Headers $auth -MaxRps 1 -MaxRetries $MaxRetries -BaseBackoffSec $BaseBackoffSec
        $accessDetails += [PSCustomObject]@{
          WorkspaceId   = $ws.id
          WorkspaceName = $ws.displayName
          AccessDetails = $resp.accessDetails
        }
      } catch {
        $r = $_.Exception.Response
        $code = if ($r) { $r.StatusCode.value__ } else { 0 }
        Write-Warning ("AccessDetails failed for {0} (HTTP {1})" -f $ws.id, $code)
      }
      $taken++
      if ($AccessGapSeconds -gt 0 -and $taken -lt $AccessMaxCount) { Start-Sleep -Seconds $AccessGapSeconds }
    }
  }

  $out = [PSCustomObject]@{
    GeneratedUtc    = (Get-Date).ToUniversalTime().ToString("o") # ISO-8601
    Workspaces      = $wsExport
    Capacities      = $capList.value
    Domains         = $domains
    WorkspaceAccess = $accessDetails
  }
  $out | ConvertTo-Json -Depth 20 | Out-File -Encoding UTF8 $OutputPath
  Write-Host ("Export finished -> {0}" -f $OutputPath)
}

# ---------- Build (read JSON -> pretty tables) ----------
function Show-Build {
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path $Path)) { throw "Input JSON not found: $Path" }
  $jsonText = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
  $data = $jsonText | ConvertFrom-Json

  $capsById = @{}
  foreach ($c in ($data.Capacities | ForEach-Object { $_ })) { $capsById[$c.id] = $c }

  $domainsById = @{}
  foreach ($d in ($data.Domains | ForEach-Object { $_ })) { $domainsById[$d.id] = $d }

  Write-Host ""
  Write-Host "=== SUMMARY ==="
  $totalWs = ($data.Workspaces | Measure-Object).Count
  $totalItem = (
    $data.Workspaces | ForEach-Object {
      $it = $_.Items
      if ($it -is [System.Array]) { $it.Count } else { 0 }
    } | Measure-Object -Sum
  ).Sum
  $totalCap = ($data.Capacities | Measure-Object).Count
  $totalDom = ($data.Domains | Measure-Object).Count
  "{0} workspaces | {1} items | {2} capacities | {3} domains" -f $totalWs, $totalItem, $totalCap, $totalDom | Write-Host

  Write-Host ""
  Write-Host "=== WORKSPACES (core) ==="
  $wsTable = $data.Workspaces | ForEach-Object {
    $w = $_.Workspace
    $items = $_.Items
    $roles = $_.RoleAssignments
    # normalize: {} -> []
    if (-not ($items -is [System.Array])) { $items = @() }
    if (-not ($roles -is [System.Array])) { $roles = @() }
    $admins = @($roles | Where-Object { $_.role -eq 'Admin' })
    [PSCustomObject]@{
      WorkspaceName = $w.displayName
      WorkspaceId   = $w.id
      Domain        = if ($w.domainId -and $domainsById.ContainsKey($w.domainId)) { $domainsById[$w.domainId].displayName } else { '' }
      Capacity      = if ($w.capacityId -and $capsById.ContainsKey($w.capacityId)) { $capsById[$w.capacityId].displayName } else { '' }
      ItemsCount    = $items.Count
      AdminsCount   = $admins.Count
    }
  }
  $wsTable | Sort-Object WorkspaceName | Format-Table -AutoSize | Out-Host

  Write-Host ""
  Write-Host "=== TOP ITEMS PER WORKSPACE (type counts) ==="
  foreach ($ws in $data.Workspaces) {
    $name = $ws.Workspace.displayName
    $items = $ws.Items
    if (-not ($items -is [System.Array])) { $items = @() }
    $groups = $items | Group-Object type | Sort-Object Count -Descending
    if ($groups.Count -gt 0) {
      Write-Host ("* {0}" -f $name)
      $groups | Select-Object Name, Count | Format-Table -AutoSize | Out-Host
    }
  }

  Write-Host ""
  Write-Host "=== ROLE ASSIGNMENTS (flattened) ==="
  $rolesFlat = foreach ($ws in $data.Workspaces) {
    $w = $ws.Workspace
    $roles = $ws.RoleAssignments
    if (-not ($roles -is [System.Array])) { $roles = @() }
    foreach ($r in $roles) {
      $upn = if ($r.principal.type -eq 'User') { $r.principal.userDetails.userPrincipalName }
             elseif ($r.principal.type -eq 'ServicePrincipal') { $r.principal.servicePrincipalDetails.aadAppId }
             else { '' }
      [PSCustomObject]@{
        Workspace    = $w.displayName
        Principal    = $r.principal.displayName
        Kind         = $r.principal.type
        Role         = $r.role
        UPN_or_AppId = $upn
      }
    }
  }
  if ($rolesFlat) { $rolesFlat | Sort-Object Workspace, Role, Principal | Format-Table -AutoSize | Out-Host }

  Write-Host ""
  Write-Host "=== CAPACITIES ==="
  $data.Capacities |
    Select-Object displayName, sku, region, state, id |
    Sort-Object displayName | Format-Table -AutoSize | Out-Host

  Write-Host ""
  Write-Host "=== DOMAINS ==="
  $data.Domains |
    Select-Object displayName, description, id |
    Sort-Object displayName | Format-Table -AutoSize | Out-Host
}

# ---------- Entry point ----------
try {
  if ($BuildAndExtract) {
    if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
      throw "BuildAndExtract requires TenantId, ClientId, ClientSecret."
    }
    Do-Export -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -OutputPath $OutputPath `
              -MaxRps $MaxRps -MaxRetries $MaxRetries -BaseBackoffSec $BaseBackoffSec `
              -IncludeAccessDetails:$IncludeAccessDetails -AccessGapSeconds $AccessGapSeconds -AccessMaxCount $AccessMaxCount
    $path = if ($InputPath) { $InputPath } else { $OutputPath }
    Show-Build -Path $path
  }
  elseif ($Build) {
    $path = if ($InputPath) { $InputPath } else { $OutputPath }
    Show-Build -Path $path
  }
  else {
    if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
      throw "Export mode requires TenantId, ClientId, ClientSecret. Or pass -Build/-BuildAndExtract."
    }
    Do-Export -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -OutputPath $OutputPath `
              -MaxRps $MaxRps -MaxRetries $MaxRetries -BaseBackoffSec $BaseBackoffSec `
              -IncludeAccessDetails:$IncludeAccessDetails -AccessGapSeconds $AccessGapSeconds -AccessMaxCount $AccessMaxCount
  }
}
catch {
  Write-Error $_.Exception.Message
  throw
}
