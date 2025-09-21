# FabricExportAndBuild.ps1

PowerShell utility to **export** Microsoft Fabric metadata (Workspaces, Items, Role Assignments, Capacities, Domains) and **render** readable console tables.

> Uses official Fabric REST APIs (Core/Admin) with pagination and 429 throttling handling (`Retry-After`).  
> References: Workspaces/Items/Role Assignments/Domains/Throttling, and OAuth2 client credentials.  
> MS Docs: Core Workspaces, Items, Role Assignments; Admin Domains; Throttling; OAuth2 client credentials. :contentReference[oaicite:13]{index=13}

## Features
- **Export** to a single JSON document (stable shape)
- **Build** readable console tables (summary, workspaces, top item types, role assignments, capacities, domains)
- **Throttling-safe** (MaxRps + exponential backoff + jitter)
- **Optional Admin** insights (workspace user/role listings) with rate caps

## Prerequisites
- PowerShell 5.1+
- **Service principal** authorized for Fabric REST (and Fabric admin for Admin endpoints)
- OAuth2 **Client Credentials** against scope `https://api.fabric.microsoft.com/.default` (no user impersonation). :contentReference[oaicite:14]{index=14}

## Security / Secrets
- **Do not** commit `TenantId`, `ClientId`, or `ClientSecret`.
- Prefer environment variables or CI/CD secret stores.

### Example (Windows PowerShell)
```powershell
$env:TENANT_ID    = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$env:CLIENT_ID    = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
$env:CLIENT_SECRET= "********"

.\FabricExportAndBuild.ps1 -BuildAndExtract `
  -TenantId  $env:TENANT_ID `
  -ClientId  $env:CLIENT_ID `
  -ClientSecret $env:CLIENT_SECRET `
  -OutputPath .\fabric-export.json `
  -MaxRps 2
```

### Usage
1) Export + Build (one shot)
```
.\FabricExportAndBuild.ps1 -BuildAndExtract `
  -TenantId "TENANT_ID" -ClientId "CLIENT_ID" -ClientSecret "CLIENT_SECRET" `
  -OutputPath ".\fabric-export.json" -MaxRps 2
```
2) Export only
```
.\FabricExportAndBuild.ps1 `
  -TenantId "TENANT_ID" -ClientId "CLIENT_ID" -ClientSecret "CLIENT_SECRET" `
  -OutputPath ".\fabric-export.json"
```
3) Build only (from existing JSON)
```
.\FabricExportAndBuild.ps1 -Build -InputPath ".\fabric-export.json"
```
### Optional Flags
```
-IncludeAccessDetails (Admin).
```
Combine with -AccessGapSeconds & -AccessMaxCount. Rate-limit note: max/hour applies. 

```
-MaxRps (default 3).
```
Lower if you receive 429. 
Microsoft Learn

```
-MaxRetries, -BaseBackoffSec
```
For fine-tuning backoff behavior.

### Sample Output (anonymized)
```
Acquiring token ...
Fetching workspaces (paged) ...
  - aps_dp01_ppe_store
  - aps_dp01_ppe_integration
  - gscp_dp01_prod_store
  - engineering_ppe
  - presentation_prod
Fetching capacities ...
Fetching domains (Admin, 25 req/min cap) ...
Export finished -> .\fabric-export.json

=== SUMMARY ===
61 workspaces | 48 items | 3 capacities | 2 domains

...
...
...
```
