# AICyberAuditBox -- applies an update at a customer site.
#
# Handles whichever component was sent: the application, the LLM, or the
# database. It works out which from the file it finds beside it, so there is
# nothing to choose and nothing to type.
#
# Everything the update guide asked an operator to do by hand is done here
# instead: verify the download, load the image, repoint the compose file,
# restart only what needs restarting, and prove the new image is the one
# running. Each of those steps has already gone wrong in the field -- a compose
# file edited in the wrong folder and an empty one created, a relative path
# resolved against C:\WINDOWS\system32, a blanket version replace that would
# have rewritten image lines the customer has no images for. So this does not
# ask for a path, does not ask which line to edit, and refuses rather than
# guess.
#
# Double-click the .bat beside this file.

# Deliberately NOT "Stop". Windows PowerShell 5.1 turns anything a native
# program writes to stderr into a NativeCommandError record, and under Stop
# that becomes a terminating error -- so `docker info` on a machine where
# Docker is not running printed a screen of PowerShell internals instead of the
# one line telling the operator to start Docker Desktop. Every docker call is
# checked by its exit code, which is the reliable signal; the .NET file calls
# throw on their own regardless of this setting.
$ErrorActionPreference = "Continue"

function Invoke-DockerQuiet {
    param([string]$ArgLine)
    cmd /c "docker $ArgLine >nul 2>&1"
    return $LASTEXITCODE
}

function Say  ($m) { Write-Host "  $m" }
function Good ($m) { Write-Host "  $m" -ForegroundColor Green }
function Warn ($m) { Write-Host "  $m" -ForegroundColor Yellow }

# Set once the compose file has actually been rewritten, so Die tells the truth
# about what state the machine is in. It used to end every failure with
# "Nothing has been changed", which is right up until the compose step and a
# lie after it -- read by someone whose product has just failed to start, who
# needs to know whether to roll anything back.
$script:ComposeChanged = $false
$script:ComposePath = $null
$script:ComposeBackup = $null

function Die ($m) {
    Write-Host ""
    Write-Host "  STOPPED: $m" -ForegroundColor Red
    Write-Host ""
    if ($script:ComposeChanged) {
        Write-Host "  The configuration WAS updated before this failed." -ForegroundColor Yellow
        Write-Host "  To put it back exactly as it was:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "      copy /y `"$($script:ComposeBackup)`" `"$($script:ComposePath)`""
        Write-Host "      docker compose up -d"
        Write-Host ""
        Write-Host "  The previous images are still on this machine, so that"
        Write-Host "  restores the versions you were running before."
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
Write-Host "  AICyberAuditBox - Update"
Write-Host "==========================================================="
Write-Host ""

# ------------------------------------------------------------ what was sent
# One table, so adding a component later is a row rather than a new script.
# ImageNames is a list because the LLM ships as one image under two tags -- the
# completion server and the embedding server are the same build started with a
# different LLM_MODE, and repointing only one of them leaves the compose naming
# an image this machine does not have.
$Components = @{
    "app" = @{
        Label      = "Application"
        ImageNames = @("aicyberauditbox-app")
        Services   = @("app")
        Container  = "aicyberauditbox_app"
        Note       = "The AI model and database are not restarted."
    }
    "llm" = @{
        Label      = "LLM (model server)"
        ImageNames = @("aicyberauditbox-llm", "aicyberauditbox-llm-embed")
        Services   = @("llm", "llm-embed")
        Container  = "aicyberauditbox_llm"
        Note       = "The model reloads on start -- allow 3-5 minutes before auditing."
    }
    "shakthidb" = @{
        Label      = "Database"
        ImageNames = @("aicyberauditbox-shakthidb")
        Services   = @("shakthidb")
        Container  = "shakthidb_service"
        Note       = "Your audit data lives in a Docker volume and is NOT replaced."
    }
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$tar = Get-ChildItem -Path $here -Filter "aicyberauditbox-*.tar" |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $tar) { Die "no aicyberauditbox-<component>-<version>.tar in this folder ($here)." }

if ($tar.Name -notmatch "^aicyberauditbox-(app|llm|shakthidb)-([0-9][0-9.]*)\.tar$") {
    Die "cannot tell what $($tar.Name) is.`n           Expected a name like aicyberauditbox-app-3.28.tar."
}
$key = $Matches[1]
$newVersion = $Matches[2]
$comp = $Components[$key]

Say "Update file : $($tar.Name)"
Say "Component   : $($comp.Label)"
Say "New version : $newVersion"
Write-Host ""

# ------------------------------------------------------------------- docker
Write-Host "[1/6] Checking Docker"
if ((Invoke-DockerQuiet "info") -ne 0) { Die "Docker is not running. Start Docker Desktop and run this again." }
Good "Docker is running."

# ----------------------------------------------------------------- checksum
Write-Host ""
Write-Host "[2/6] Verifying the file arrived intact"
$sidecar = "$($tar.FullName).sha256"
if (Test-Path $sidecar) {
    $expected = (Get-Content $sidecar -Raw).Trim().ToLower() -replace '[^0-9a-f]', ''
    $actual = (Get-FileHash -Algorithm SHA256 -Path $tar.FullName).Hash.ToLower()
    if ($expected -ne $actual) {
        Die "the file is damaged (checksum does not match). Ask for it to be sent again.`n           expected $expected`n           actual   $actual"
    }
    Good "Checksum matches."
} else {
    Warn "No .sha256 beside the tar -- skipping the integrity check."
}

# ------------------------------------------------------------------- backup
# Taken before anything is touched, because that is the only moment it is worth
# anything. Until now a site had no backup at all: run_all.bat dumps the
# database on the developer's machine, and nothing of the kind ever shipped.
#
# Both halves or neither. The audit results are rows in the database; the
# evidence those results cite -- screenshots, PDFs -- are files in the app's
# data volume. Restoring one without the other leaves findings quoting
# documents that are gone, or documents nobody assessed. For an audit product
# that is worse than having no backup, because it looks like a complete one.
Write-Host ""
Write-Host "[3/6] Backing up before anything is changed"

$stamp = Get-Date -Format "yyyyMMdd-HHmm"
$backupRoot = Join-Path $here "backups"
$dbFile = Join-Path $backupRoot "db_before_$newVersion`_$stamp.sql"
$filesDir = Join-Path $backupRoot "files_before_$newVersion`_$stamp"

$dbUp = ((Invoke-DockerQuiet "inspect -f {{.State.Running}} shakthidb_service") -eq 0)
if (-not $dbUp) {
    Warn "The database container is not running, so there is nothing to back up yet."
    Warn "This is normal on a site that has not been started."
} else {
    New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null

    Say "Audit results -> $(Split-Path -Leaf $dbFile)"
    # pg_dumpall, not pg_dump of POSTGRES_DB.
    #
    # The compose file sets POSTGRES_DB=shakthidb, and that is NOT where the
    # audits are. The application works in shakthidb_master, with
    # shakthidb_slave1 and _slave2 replicated from it, and shakthidb itself
    # holds almost nothing. Dumping the named database therefore exited 0,
    # produced valid SQL, and captured none of the customer's work -- measured
    # on a real installation: 4 KB and two tables, beside 1,922 findings in
    # master that the backup never touched. A backup that looks complete and is
    # empty is worse than none, because nobody checks it until they need it.
    #
    # cmd, not a PowerShell redirect: PowerShell 5.1 writes UTF-16 with a BOM
    # when it redirects, and psql will not read that back.
    cmd /c "docker exec shakthidb_service pg_dumpall -U postgres -p 15234 > `"$dbFile`" 2>nul"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $dbFile) -or (Get-Item $dbFile).Length -lt 1024) {
        Die "the database backup failed or came out empty, so this update has not been applied.`n           Nothing has been changed. Check the database container is healthy:`n               docker compose ps"
    }
    # Prove the real database is in there, rather than trusting a size. This is
    # the check that would have caught the wrong-database dump above.
    if (-not (Select-String -Path $dbFile -Pattern "shakthidb_master" -Quiet -ErrorAction SilentlyContinue)) {
        Die "the database backup does not contain shakthidb_master, which is where the`n           audits live. Not proceeding on a backup that would not restore anything.`n           Saved for inspection: $dbFile"
    }
    Good ("Audit results saved ({0:N1} MB, includes shakthidb_master)" -f ((Get-Item $dbFile).Length / 1MB))

    Say "Uploaded evidence -> $(Split-Path -Leaf $filesDir)"
    # docker cp reads a stopped container as happily as a running one, so this
    # works whatever state the app is in -- it only needs the container to
    # exist. A site that has never been started has no evidence to lose.
    if ((Invoke-DockerQuiet "inspect aicyberauditbox_app") -ne 0) {
        Warn "The application container does not exist yet, so there is no uploaded"
        Warn "evidence to back up. The audit results were saved."
    } else {
        cmd /c "docker cp aicyberauditbox_app:/app/data `"$filesDir`" >nul 2>&1"
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $filesDir)) {
            Die "the evidence backup failed, so this update has not been applied.`n           The audit results were saved to:`n               $dbFile`n           but without the evidence files that backup is not a complete one."
        }
    }
    if (Test-Path $filesDir) {
        $mb = (Get-ChildItem $filesDir -Recurse -File -ErrorAction SilentlyContinue |
               Measure-Object -Property Length -Sum).Sum / 1MB
        Good ("Uploaded evidence saved ({0:N1} MB)" -f $mb)
    }
    Write-Host ""
    Say "Both are in:  $backupRoot"
    Say "Keep them until the update has been used and looks right."
}

# --------------------------------------------------------------------- load
Write-Host ""
Write-Host "[4/6] Loading the new image (several minutes, prints nothing while it works)"
docker load -i $tar.FullName
if ($LASTEXITCODE -ne 0) { Die "docker load failed." }
foreach ($img in $comp.ImageNames) {
    if ((Invoke-DockerQuiet "image inspect ${img}:$newVersion") -ne 0) {
        Die "the image did not load. Expected ${img}:$newVersion."
    }
}
Good ("Loaded: " + (($comp.ImageNames | ForEach-Object { "${_}:$newVersion" }) -join ", "))

# ------------------------------------------------------------------ compose
Write-Host ""
Write-Host "[5/6] Pointing the installation at the new image"

# Ask Docker where the running stack was started from, rather than searching the
# disk. A search finds copies -- an old extracted bundle, a spare in "New
# folder" -- and editing the wrong one changes nothing while appearing to work.
$composePath = $null
try {
    $projects = docker compose ls --format json 2>$null | ConvertFrom-Json
    foreach ($p in $projects) {
        $cfg = ($p.ConfigFiles -split ",")[0].Trim()
        if ($cfg -and (Test-Path $cfg)) {
            if ([IO.File]::ReadAllText($cfg) -match "aicyberauditbox-") { $composePath = $cfg; break }
        }
    }
} catch { }
if (-not $composePath) {
    $local = Join-Path $here "docker-compose.yml"
    if ((Test-Path $local) -and ([IO.File]::ReadAllText($local) -match "aicyberauditbox-")) {
        $composePath = $local
    }
}
if (-not $composePath) {
    Die "could not find the docker-compose.yml this installation runs from.`n           Start the product once, then run this again -- or run this from the install folder."
}
Say "Compose file: $composePath"
$script:ComposePath = $composePath

$content = [IO.File]::ReadAllText($composePath)

# Every image line this update owns, and its current version.
$targets = @{}
foreach ($img in $comp.ImageNames) {
    $m = [regex]::Match($content, "image:\s*$([regex]::Escape($img)):([0-9][0-9.]*)")
    if (-not $m.Success) { Die "no ${img} image line in the compose file." }
    $targets[$img] = $m.Groups[1].Value
}

# Anything this update does NOT own must come out byte-identical. This is the
# check that would have caught a blanket version replace rewriting the LLM
# lines during an application update.
$untouched = @()
foreach ($other in @("aicyberauditbox-app", "aicyberauditbox-llm", "aicyberauditbox-llm-embed", "aicyberauditbox-shakthidb")) {
    if ($comp.ImageNames -notcontains $other) { $untouched += $other }
}
function Get-VersionsOf ($text, $img) {
    ([regex]::Matches($text, "$([regex]::Escape($img)):([0-9][0-9.]*)") |
        ForEach-Object { $_.Groups[1].Value }) -join ","
}
$before = @{}
foreach ($img in $untouched) { $before[$img] = Get-VersionsOf $content $img }

$needsChange = $false
foreach ($img in $comp.ImageNames) { if ($targets[$img] -ne $newVersion) { $needsChange = $true } }

if (-not $needsChange) {
    Good "Already pointing at $newVersion -- no change needed."
} else {
    $backup = "$composePath.before-$key-$newVersion.bak"
    Copy-Item $composePath $backup -Force
    $script:ComposeBackup = $backup
    Say "Backup     : $backup"

    $updated = $content
    foreach ($img in $comp.ImageNames) {
        $updated = $updated -replace "$([regex]::Escape($img)):$([regex]::Escape($targets[$img]))",
                                     "${img}:$newVersion"
    }
    # UTF-8 with no BOM: a BOM at the top of a compose file is read as part of
    # the first key and Docker rejects the file.
    [IO.File]::WriteAllText($composePath, $updated, (New-Object Text.UTF8Encoding $false))

    $check = [IO.File]::ReadAllText($composePath)
    foreach ($img in $comp.ImageNames) {
        if ($check -notmatch "image:\s*$([regex]::Escape($img)):$([regex]::Escape($newVersion))") {
            Copy-Item $backup $composePath -Force
            Die "the compose file did not update as expected. It has been restored from the backup."
        }
    }
    foreach ($img in $untouched) {
        if ((Get-VersionsOf $check $img) -ne $before[$img]) {
            Copy-Item $backup $composePath -Force
            Die "$img would have been changed, and this update does not own it. Restored from the backup."
        }
    }
    $script:ComposeChanged = $true
    Good ("Updated to $newVersion. Untouched: " + ($untouched -join ", "))
}

# ------------------------------------------------------------------ restart
Write-Host ""
Write-Host "[6/6] Restarting $($comp.Label)"
Push-Location (Split-Path -Parent $composePath)
try {
    docker compose up -d @($comp.Services)
    if ($LASTEXITCODE -ne 0) {
        Die "the service did not restart. The message just above says why.`n           A missing POSTGRES_PASSWORD in the .env beside the compose is the`n           usual cause, and is nothing to do with this update."
    }
} finally {
    Pop-Location
}

# `docker compose up` reports success whether or not the compose edit saved, so
# the only proof is what the running container is actually built from.
$running = (docker inspect --format "{{.Config.Image}}" $comp.Container 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $running) { Die "could not read the running container's image." }
$running = $running.Trim()
$expectImage = "$($comp.ImageNames[0]):$newVersion"
if ($running -ne $expectImage) {
    Die "$($comp.Container) is still running $running, not $expectImage."
}

Write-Host ""
Write-Host "==========================================================="
Good "Update complete. $($comp.Label) is running $running"
Write-Host "==========================================================="
Write-Host ""
Say $comp.Note
Write-Host ""
if ($script:ComposeBackup) {
    Say "To roll back:"
    Say "  copy /y `"$($script:ComposeBackup)`" `"$($script:ComposePath)`""
    Say "  docker compose up -d"
    Write-Host ""
}
