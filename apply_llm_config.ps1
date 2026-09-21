# AICyberAuditBox -- applies an LLM startup-settings update.
#
# The model weights are not in this package and do not need to be. The new
# settings are a few KB of shell script, layered onto the LLM image this
# machine already holds, so the ~12.6GB of weights are inherited rather than
# transferred. The rebuild takes seconds and needs no internet.
#
# Double-click apply_llm_config.bat beside this file.

$ErrorActionPreference = "Continue"

function Invoke-DockerQuiet {
    param([string]$ArgLine)
    cmd /c "docker $ArgLine >nul 2>&1"
    return $LASTEXITCODE
}

function Say  ($m) { Write-Host "  $m" }
function Good ($m) { Write-Host "  $m" -ForegroundColor Green }

$script:ComposeChanged = $false
$script:ComposePath = $null
$script:ComposeBackup = $null

function Die ($m) {
    Write-Host ""
    Write-Host "  STOPPED: $m" -ForegroundColor Red
    Write-Host ""
    if ($script:ComposeChanged) {
        Write-Host "  The configuration WAS updated before this failed." -ForegroundColor Yellow
        Write-Host "      copy /y `"$($script:ComposeBackup)`" `"$($script:ComposePath)`""
        Write-Host "      docker compose up -d"
    } else {
        Write-Host "  Nothing has been changed."
    }
    Write-Host ""
    Write-Host "  Send this message to your supplier."
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "==========================================================="
Write-Host "  AICyberAuditBox - LLM Startup Settings Update"
Write-Host "==========================================================="
Write-Host ""

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($need in @("Dockerfile.llm.rebase", "docker\llm-entrypoint.sh")) {
    if (-not (Test-Path (Join-Path $here $need))) { Die "$need is missing from this folder." }
}

Write-Host "[1/4] Checking Docker"
if ((Invoke-DockerQuiet "info") -ne 0) { Die "Docker is not running. Start Docker Desktop and run this again." }
Good "Docker is running."

# ------------------------------------------------- find the current install
Write-Host ""
Write-Host "[2/4] Finding your installation"
$composePath = $null
try {
    $projects = docker compose ls --format json 2>$null | ConvertFrom-Json
    foreach ($p in $projects) {
        $cfg = ($p.ConfigFiles -split ",")[0].Trim()
        if ($cfg -and (Test-Path $cfg) -and ([IO.File]::ReadAllText($cfg) -match "aicyberauditbox-llm:")) {
            $composePath = $cfg; break
        }
    }
} catch { }
if (-not $composePath) { Die "could not find the docker-compose.yml this installation runs from.`n           Start the product once, then run this again." }
$script:ComposePath = $composePath
Say "Compose file: $composePath"

$content = [IO.File]::ReadAllText($composePath)
$m = [regex]::Match($content, 'image:\s*aicyberauditbox-llm:([0-9][0-9.]*)')
if (-not $m.Success) { Die "no aicyberauditbox-llm image line in the compose file." }
$baseVersion = $m.Groups[1].Value
Say "Current LLM : $baseVersion"

if ((Invoke-DockerQuiet "image inspect aicyberauditbox-llm:$baseVersion") -ne 0) {
    Die "aicyberauditbox-llm:$baseVersion is named in the compose file but is not on this machine."
}

# The new tag: bump the last number of the base, so a settings change is
# visibly a new version without anyone having to invent one.
$parts = $baseVersion.Split(".")
$parts[-1] = [string]([int]$parts[-1] + 1)
$newVersion = ($parts -join ".")
Say "New LLM     : $newVersion  (settings only; weights inherited)"

# ----------------------------------------------------------------- rebuild
Write-Host ""
Write-Host "[3/4] Rebuilding on top of the image you already have (seconds)"
Push-Location $here
try {
    docker build -f Dockerfile.llm.rebase --build-arg LLM_BASE_IMAGE=aicyberauditbox-llm:$baseVersion -t aicyberauditbox-llm:$newVersion .
    if ($LASTEXITCODE -ne 0) { Die "the rebuild failed." }
} finally { Pop-Location }

# The embedding server is the same image under a second tag, started with a
# different LLM_MODE. Both must move together or the compose names an image
# that does not exist.
docker tag aicyberauditbox-llm:$newVersion aicyberauditbox-llm-embed:$newVersion
if ($LASTEXITCODE -ne 0) { Die "could not tag the embedding image." }
Good "Built aicyberauditbox-llm:$newVersion and -llm-embed:$newVersion"

# ----------------------------------------------------------------- compose
Write-Host ""
Write-Host "[4/4] Switching over and restarting the model servers"
$backup = "$composePath.before-llm-$newVersion.bak"
Copy-Item $composePath $backup -Force
$script:ComposeBackup = $backup

$updated = $content -replace "aicyberauditbox-llm:$([regex]::Escape($baseVersion))", "aicyberauditbox-llm:$newVersion"
$updated = $updated -replace "aicyberauditbox-llm-embed:[0-9][0-9.]*", "aicyberauditbox-llm-embed:$newVersion"
[IO.File]::WriteAllText($composePath, $updated, (New-Object Text.UTF8Encoding $false))

$check = [IO.File]::ReadAllText($composePath)
# The application and database lines are not ours to touch.
foreach ($img in @("aicyberauditbox-app", "aicyberauditbox-shakthidb")) {
    $b = ([regex]::Matches($content, "$img`:([0-9][0-9.]*)") | ForEach-Object { $_.Groups[1].Value }) -join ","
    $a = ([regex]::Matches($check,   "$img`:([0-9][0-9.]*)") | ForEach-Object { $_.Groups[1].Value }) -join ","
    if ($b -ne $a) {
        Copy-Item $backup $composePath -Force
        Die "$img would have been changed, and this update does not own it. Restored from the backup."
    }
}
$script:ComposeChanged = $true

Push-Location (Split-Path -Parent $composePath)
try {
    docker compose up -d llm llm-embed
    if ($LASTEXITCODE -ne 0) { Die "the model servers did not restart. The message above says why." }
} finally { Pop-Location }

$running = (docker inspect --format "{{.Config.Image}}" aicyberauditbox_llm 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $running) { Die "could not read the running container's image." }
if ($running.Trim() -ne "aicyberauditbox-llm:$newVersion") {
    Die "the LLM is still running $($running.Trim()), not aicyberauditbox-llm:$newVersion."
}

Write-Host ""
Write-Host "==========================================================="
Good "Done. LLM now running aicyberauditbox-llm:$newVersion"
Write-Host "==========================================================="
Write-Host ""
Say "The model reloads on start -- allow 3-5 minutes before running an audit."
Say "Check it sized itself correctly:"
Say "  docker compose logs llm | findstr `"LLM ENTRYPOINT`""
Say "The last line should read: = 32768 tokens per request"
Write-Host ""
Say "To roll back:"
Say "  copy /y `"$backup`" `"$composePath`""
Say "  docker compose up -d llm llm-embed"
Write-Host ""
