# update_bundle.ps1
#
# Rebuilds the given service image(s) at a new version tag, bumps that tag in
# both docker-compose.yml and docker-compose.customer.yml, then exports a
# fresh customer bundle tar containing all 4 built images (at their current,
# possibly-mixed tags) plus the stock redis image.
#
# Delivery = TWO files shipped to the customer:
#   aicyberauditbox_bundle_vX.X.tar          (Docker images, ~7 GB)
#   aicyberauditbox_bundle_vX.X_companion.zip (docker-compose.customer.yml + QUICKSTART, ~50 KB)
#
# Usage:
#   .\update_bundle.ps1 -Version 3.8                     (rebuilds app only -- the common case)
#   .\update_bundle.ps1 -Version 3.8 -Services app,llm   (rebuilds app + llm)
#   .\update_bundle.ps1 -Version 3.8 -Services shakthidb (rebuilds only the DB image)
#
# Valid service names: app, llm, llm-embed, shakthidb

param(
    [Parameter(Mandatory=$true)][string]$Version,
    [string[]]$Services = @("app"),
    # Routine update mode: export ONLY the images just rebuilt (named in -Services)
    # instead of the full 5-image ~7GB set. Use for scenario A/B updates (app code,
    # additive schema change) where shakthidb/redis/llm/llm-embed are untouched and
    # already running at the customer site. Omit for first-time / disaster-recovery
    # installs, which still need the full bundle.
    [switch]$DeltaOnly
)

$ErrorActionPreference = "Stop"

$dockerfileMap = @{
    "app"       = "Dockerfile.app"
    "llm"       = "Dockerfile.llm"
    "llm-embed" = "Dockerfile.llm"
    "shakthidb" = "Dockerfile"
}

foreach ($svc in $Services) {
    if (-not $dockerfileMap.ContainsKey($svc)) {
        Write-Error "Unknown service '$svc'. Valid: app, llm, llm-embed, shakthidb"
        exit 1
    }
}

# ── Step 1: Build service images & bump compose version tags ──────────────────
foreach ($svc in $Services) {
    $df    = $dockerfileMap[$svc]
    $image = "aicyberauditbox-${svc}:${Version}"

    Write-Host "=== Building $image from $df ===" -ForegroundColor Cyan
    docker build -f $df -t $image .
    if ($LASTEXITCODE -ne 0) { Write-Error "Build failed for $svc"; exit 1 }

    foreach ($composeFile in @("docker-compose.yml", "docker-compose.customer.yml")) {
        if (Test-Path $composeFile) {
            (Get-Content $composeFile) -replace "aicyberauditbox-${svc}:\S+", "aicyberauditbox-${svc}:${Version}" |
                Set-Content $composeFile -Encoding utf8
        }
    }
    Write-Host "Bumped $svc to :$Version in compose files." -ForegroundColor Green
}

# ── Resolve current image tags from customer compose file ────────────────────
$targetCompose = if (Test-Path "docker-compose.customer.yml") { "docker-compose.customer.yml" } else { "docker-compose.yml" }
$composeContent = Get-Content $targetCompose -Raw

function Get-ImageRef([string]$svc) {
    if ($composeContent -match "aicyberauditbox-${svc}:\S+") {
        return $matches[0]
    }
    Write-Error "Could not find image tag for $svc in $targetCompose"
    exit 1
}

if ($DeltaOnly) {
    # Only the image(s) actually rebuilt this run -- shakthidb/redis/llm/llm-embed
    # are untouched and already running at the customer site, so there's nothing
    # to gain (and ~7GB to lose) by re-shipping them for a routine app-only update.
    $images = @($Services | ForEach-Object { Get-ImageRef $_ })
    $svcTag = ($Services -join "-")
    $tarName      = "aicyberauditbox_delta_${svcTag}_v${Version}.tar"
    $readmeFile   = "UPDATE_v${Version}.md"
    $companionZip = "aicyberauditbox_delta_${svcTag}_v${Version}_companion.zip"
} else {
    $images = @(
        (Get-ImageRef "shakthidb"),
        (Get-ImageRef "llm"),
        (Get-ImageRef "llm-embed"),
        (Get-ImageRef "app"),
        "redis:7-alpine"
    )
    $tarName      = "aicyberauditbox_bundle_v${Version}.tar"
    $readmeFile   = "QUICKSTART_v${Version}.md"
    $companionZip = "aicyberauditbox_bundle_v${Version}_companion.zip"
}

# ── Step 2: Export Docker images to tar ───────────────────────────────────────
Write-Host ""
Write-Host "=== Exporting Docker images -> $tarName ===" -ForegroundColor Cyan
Write-Host "Images: $($images -join ', ')"

foreach ($img in $images) {
    if ($img.StartsWith("redis:")) {
        Write-Host "Ensuring base image '$img' is present..." -ForegroundColor Yellow
        docker pull $img
    }
}

docker save $images -o $tarName
if ($LASTEXITCODE -ne 0) { Write-Error "docker save failed"; exit 1 }
$tarGB = [math]::Round((Get-Item $tarName).Length / 1GB, 2)
Write-Host "Images saved -> $tarName ($tarGB GB)" -ForegroundColor Green

# ── Step 3: Write customer quickstart / update README ─────────────────────────
$imageList = ($images | ForEach-Object { "- $_" }) -join "`n"

if ($DeltaOnly) {
    $svcList = ($Services -join ", ")
    $restartCmd = ($Services -join " ")
    $readmeContent = @"
# AICyberAuditBox v${Version} - Delta Update ($svcList)

## What's in this delivery
  1. $tarName          -- Only the rebuilt image(s): $svcList
  2. $companionZip -- This guide + updated docker-compose.customer.yml

Postgres, Redis, and any LLM service NOT listed above are untouched and stay
running throughout this update -- this is a routine app-code or additive-schema
change (see the Rolling Update Playbook, scenarios A/B). If this delivery is for
a structural database change (renamed/dropped/retyped column), follow scenario C
instead: back up first, run the migration script, then apply this update.

## Apply this update

  Step 1 - Load only the new image(s):
    docker load -i $tarName

  Step 2 - Replace docker-compose.customer.yml with the one in this delivery's
  companion zip (it has the new image tag already bumped for: $svcList).

  Step 3 - Restart ONLY the updated service(s) -- everything else keeps running:
    docker compose -f docker-compose.customer.yml up -d $restartCmd

  Step 4 - Confirm the schema healed (if applicable) and the app is serving:
    docker compose -f docker-compose.customer.yml logs app --tail 40
    curl -sf http://localhost:8000/ ; echo

## Rollback
Old image tags are never deleted -- to revert, edit docker-compose.customer.yml
back to the previous version tag for $svcList, then:
    docker compose -f docker-compose.customer.yml up -d $restartCmd

## Included images
$imageList

## Support
Contact your AICyberAuditBox deployment team for assistance.
"@
} else {
    $readmeContent = @"
# AICyberAuditBox v${Version} - Customer Quickstart

## What's in your delivery
You received two files:
  1. aicyberauditbox_bundle_v${Version}.tar      -- All Docker images (~7 GB, air-gapped)
  2. aicyberauditbox_bundle_v${Version}_companion.zip -- This guide + docker-compose.customer.yml

## Prerequisites
- Docker Engine 24+ and Docker Compose v2+
- Minimum 24 GB RAM (32 GB recommended for full 8-slot LLM concurrency)
- Linux or Windows Server with Docker Desktop

## Deploy (offline / air-gapped)

  Step 1 - Load all images (one-time, no internet needed):
    docker load -i aicyberauditbox_bundle_v${Version}.tar

  Step 2 - Start all services:
    docker compose -f docker-compose.customer.yml up -d

  Step 3 - Verify all containers are running:
    docker compose -f docker-compose.customer.yml ps

## Access
  Web UI  : http://localhost:8000
  Admin   : username=admin  password=admin123  (change on first login)

## Day-to-day commands
  Stop:     docker compose -f docker-compose.customer.yml down
  Logs:     docker compose -f docker-compose.customer.yml logs -f app
  Restart:  docker compose -f docker-compose.customer.yml up -d

## Upgrading to a new version
  Routine app-only update? Use a -DeltaOnly bundle instead of this full one --
  see UPDATE_v<version>.md in that delivery. Only re-run the full install below
  for first-time setup or disaster recovery.
  1. docker load -i aicyberauditbox_bundle_vNEW.tar
  2. Replace docker-compose.customer.yml with the new one from the companion zip
  3. docker compose -f docker-compose.customer.yml up -d
  (Your database and uploaded data are preserved in Docker volumes: pgdata, app_data)

## Included images
$imageList

## Support
Contact your AICyberAuditBox deployment team for assistance.
"@
}
$readmeContent | Set-Content $readmeFile -Encoding utf8
Write-Host "Quickstart README written -> $readmeFile" -ForegroundColor Green

# ── Step 4: Zip ONLY the small companion files (no tar copy - saves disk space) ──
Write-Host ""
Write-Host "=== Creating companion ZIP -> $companionZip ===" -ForegroundColor Cyan

if (Test-Path $companionZip) { Remove-Item $companionZip -Force }

# Compress-Archive is fine here - these files are < 100 KB total
$companionFiles = @("docker-compose.customer.yml", $readmeFile)
if (Test-Path "DEPLOYMENT_GUIDE.md") { $companionFiles += "DEPLOYMENT_GUIDE.md" }
Compress-Archive -Path $companionFiles `
                 -DestinationPath $companionZip `
                 -CompressionLevel Optimal

if (-not (Test-Path $companionZip)) { Write-Error "Companion ZIP creation failed"; exit 1 }
$zipKB = [math]::Round((Get-Item $companionZip).Length / 1KB, 1)
Write-Host "Companion ZIP created -> $companionZip ($zipKB KB)" -ForegroundColor Green

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
if ($DeltaOnly) {
    Write-Host "  DELTA UPDATE COMPLETE -- ship BOTH files to the customer:" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  [1]  $tarName  ($tarGB GB)" -ForegroundColor White
    Write-Host "  [2]  $companionZip  ($zipKB KB)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Customer instructions:" -ForegroundColor Yellow
    Write-Host "    1. Place both files in the same folder" -ForegroundColor White
    Write-Host "    2. Unzip $companionZip" -ForegroundColor White
    Write-Host "    3. docker load -i $tarName" -ForegroundColor White
    Write-Host "    4. docker compose -f docker-compose.customer.yml up -d $($Services -join ' ')" -ForegroundColor White
    Write-Host "    (Postgres/Redis/other LLM services are NOT restarted)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Done." -ForegroundColor Green
} else {
    Write-Host "  BUNDLE COMPLETE -- ship BOTH files to the customer:" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  [1]  $tarName  ($tarGB GB)" -ForegroundColor White
    Write-Host "  [2]  $companionZip  ($zipKB KB)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Customer instructions:" -ForegroundColor Yellow
    Write-Host "    1. Place both files in the same folder" -ForegroundColor White
    Write-Host "    2. Unzip $companionZip" -ForegroundColor White
    Write-Host "    3. docker load -i $tarName" -ForegroundColor White
    Write-Host "    4. docker compose -f docker-compose.customer.yml up -d" -ForegroundColor White
    Write-Host "    5. Open http://localhost:8000" -ForegroundColor White
    Write-Host ""
    Write-Host "  Done." -ForegroundColor Green
}
