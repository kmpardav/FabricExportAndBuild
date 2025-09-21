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
