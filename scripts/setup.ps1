<#
.SYNOPSIS
  Guided setup for Windows (Docker Desktop). Safe to run again.

.DESCRIPTION
  Asks a few questions, writes .env, creates .\secrets, builds the gate image,
  stores your password only as an argon2id hash, and starts the stack.

  Easiest: double-click setup.bat in the main folder. Or, in PowerShell:
    powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
    powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -ResetPassword
#>
[CmdletBinding()]
param([switch]$ResetPassword)

# Native tools (docker) write progress to stderr; don't let that abort the script.
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version 2.0
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$OnWindows = ($env:OS -eq 'Windows_NT')

function Say([string]$m)  { Write-Host $m }
function Step([string]$m) { Write-Host ''; Write-Host "== $m ==" -ForegroundColor Cyan }
function Ok([string]$m)   { Write-Host "  OK  $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "  !!  $m" -ForegroundColor Yellow }
function Stop-Setup([string]$m) {
  Write-Host ''; Write-Host "STOPPED: $m" -ForegroundColor Red
  exit 1
}
function Ask([string]$q, [string]$def = '') {
  if ($def) { $a = Read-Host "$q [$def]"; if (-not $a) { $a = $def } } else { $a = Read-Host $q }
  if ($null -eq $a) { $a = '' }
  return $a.Trim().Trim('"', "'").Trim()
}
function Ask-Secret([string]$q) {
  $ss = Read-Host $q -AsSecureString
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
function Yes-No([string]$q, [string]$def) {
  $a = Read-Host "$q [$def]"; if (-not $a) { $a = $def }
  return ($a -match '^[Yy]')
}
function Write-Secret([string]$name, [byte[]]$bytes) {
  $path = Join-Path $Root "secrets\$name"
  if (Test-Path -LiteralPath $path) { Set-ItemProperty -LiteralPath $path -Name IsReadOnly -Value $false; Remove-Item -LiteralPath $path -Force }
  [IO.File]::WriteAllBytes($path, $bytes)
  if (-not $OnWindows) { & chmod 444 $path }
}
function Text-Bytes([string]$s) { return $Utf8NoBom.GetBytes($s) }
function Random-Bytes([int]$n) {
  $b = New-Object byte[] $n
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($b); $rng.Dispose()
  return ,$b
}

# ------------------------------------------------------------------ .env helpers
function Get-EnvValue([string]$key) {
  if (-not (Test-Path .env)) { return '' }
  foreach ($line in [IO.File]::ReadAllLines((Join-Path $Root '.env'))) {
    if ($line.StartsWith("$key=")) { return $line.Substring($key.Length + 1) }
  }
  return ''
}
function Set-EnvValue([string]$key, [string]$val) {
  $path = Join-Path $Root '.env'
  $lines = New-Object System.Collections.Generic.List[string]
  $found = $false
  foreach ($line in [IO.File]::ReadAllLines($path)) {
    if ($line.StartsWith("$key=")) { $lines.Add("$key=$val"); $found = $true } else { $lines.Add($line.TrimEnd("`r")) }
  }
  if (-not $found) { $lines.Add("$key=$val") }
  [IO.File]::WriteAllText($path, (($lines -join "`n") + "`n"), $Utf8NoBom)
}
function Set-ComposeFile {
  $sep = [IO.Path]::PathSeparator   # ';' on Windows
  Set-EnvValue 'COMPOSE_FILE' ("docker-compose.yml{0}compose.desktop.yml" -f $sep)
}
function Get-LocalIanaZone {
  $id = [TimeZoneInfo]::Local.Id
  if ($id -match '/') { return $id }
  $iana = $null
  try { if ([TimeZoneInfo]::TryConvertWindowsIdToIanaId($id, [ref]$iana)) { return $iana } } catch { }
  $map = @{
    'Eastern Standard Time' = 'America/New_York'; 'Central Standard Time' = 'America/Chicago'
    'Mountain Standard Time' = 'America/Denver'; 'US Mountain Standard Time' = 'America/Phoenix'
    'Pacific Standard Time' = 'America/Los_Angeles'; 'Alaskan Standard Time' = 'America/Anchorage'
    'Hawaiian Standard Time' = 'Pacific/Honolulu'; 'GMT Standard Time' = 'Europe/London'
    'W. Europe Standard Time' = 'Europe/Berlin'; 'UTC' = 'Etc/UTC'
  }
  if ($map.ContainsKey($id)) { return $map[$id] }
  return 'Etc/UTC'
}

# ------------------------------------------------------------------ steps
function Test-Docker {
  Step '1/6  Checking Docker'
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Stop-Setup ("Docker isn't installed (or this window can't find it).`n" +
      "  Install Docker Desktop from https://www.docker.com/products/docker-desktop/ , restart the PC if asked,`n" +
      "  open Docker Desktop once, then close this window and run setup again.")
  }
  $null = & docker info 2>$null
  if ($LASTEXITCODE -ne 0) {
    Stop-Setup ("Docker is installed but not running.`n" +
      "  Open Docker Desktop from the Start menu, wait for 'Engine running' (green) at the bottom left, then run setup again.")
  }
  $null = & docker compose version 2>$null
  if ($LASTEXITCODE -ne 0) { Stop-Setup "'docker compose' is missing. Update Docker Desktop and try again." }
  $ver = (& docker version --format '{{.Server.Version}}' 2>$null)
  Ok "Docker $ver is running"
  if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    Warn 'This PC has an ARM chip. The Signal image is x86-64 only, so it runs emulated and may be slow or fail.'
  }
  if ($Root -match 'OneDrive|Dropbox|Google Drive|iCloud') {
    Warn "This folder looks cloud-synced ($Root). Your secrets would be uploaded."
    Warn "Move the folder to $env:USERPROFILE\signal-web-gate and run setup from there."
    if (-not (Yes-No 'Continue anyway?' 'n')) { exit 1 }
  }
}

function Set-Settings {
  Step '2/6  Your settings (.env)'
  if ((Test-Path .env) -and -not (Select-String -Path .env -Pattern 'REPLACE_WITH|YOUR_TEAM|signal\.example\.com' -Quiet)) {
    Say 'You already have a .env file:'
    Get-Content .env | Where-Object { $_ -match '^(GATE_ORIGIN|GATE_TEAM|GATE_ALLOWED_EMAIL|TZ)=' } | ForEach-Object { Say "    $_" }
    if (Yes-No 'Keep these settings?' 'y') { Set-ComposeFile; Ok 'Kept .env'; return }
  }
  if (-not (Test-Path .env)) {
    $example = [IO.File]::ReadAllText((Join-Path $Root '.env.example')).Replace("`r`n", "`n")
    [IO.File]::WriteAllText((Join-Path $Root '.env'), $example, $Utf8NoBom)
  }
  Say 'Answer with what you copied from Cloudflare (see the walkthrough, steps 3-5).'
  while ($true) {
    $hostName = (Ask '1) Your Signal web address, e.g. signal.example.com').ToLowerInvariant()
    $hostName = $hostName -replace '^https?://', '' -replace '/.*$', ''
    if ($hostName -match '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$') { break }
    Warn "That doesn't look like a web address. Type only the name, like signal.example.com"
  }
  while ($true) {
    $team = (Ask '2) Your Cloudflare team name (the NAME in NAME.cloudflareaccess.com)').ToLowerInvariant()
    $team = $team -replace '^https?://', '' -replace '/.*$', '' -replace '\.cloudflareaccess\.com$', ''
    if ($team -match '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$') { break }
    Warn 'Use just the team name, for example: myfamily'
  }
  while ($true) {
    $aud = Ask '3) The Application Audience (AUD) tag of your Access application'
    if ($aud -match '^[A-Za-z0-9]{32,128}$') { break }
    Warn 'The AUD tag is a long string of letters and numbers (usually 64). Copy it again.'
  }
  while ($true) {
    $email = ((Ask '4) Email address(es) allowed in (comma-separated, same as the Access policy)') -replace '\s', '').ToLowerInvariant()
    if ($email -match '^[^@,]+@[^@,]+\.[^@,]+(,[^@,]+@[^@,]+\.[^@,]+)*$') { break }
    Warn "That doesn't look like an email address."
  }
  $tz = Ask '5) Time zone' (Get-LocalIanaZone)
  Set-EnvValue 'GATE_ORIGIN' "https://$hostName"
  Set-EnvValue 'GATE_TEAM' "https://$team.cloudflareaccess.com"
  Set-EnvValue 'GATE_AUD' $aud
  Set-EnvValue 'GATE_ALLOWED_EMAIL' $email
  Set-EnvValue 'TZ' $tz
  Set-ComposeFile
  Ok 'Saved .env'
}

function New-Secrets {
  Step '3/6  Secrets (saved in .\secrets, never uploaded)'
  $null = New-Item -ItemType Directory -Force -Path (Join-Path $Root 'secrets')
  if (-not $OnWindows) { & chmod 700 (Join-Path $Root 'secrets') }
  if ((Test-Path secrets\session_key) -and (Get-Item secrets\session_key).Length -gt 0) { Ok 'Session key already exists' }
  else { Write-Secret 'session_key' (Random-Bytes 32); Ok 'Created a session key' }

  if ((Test-Path secrets\upstream_password) -and (Test-Path secrets\upstream_basic)) { Ok 'Internal Signal login already exists' }
  else {
    $user = Get-EnvValue 'UPSTREAM_USER'; if (-not $user) { $user = 'signal' }
    $pw = ((Random-Bytes 32) | ForEach-Object { $_.ToString('x2') }) -join ''
    Write-Secret 'upstream_password' (Text-Bytes $pw)
    Write-Secret 'upstream_basic' (Text-Bytes ([Convert]::ToBase64String((Text-Bytes "${user}:$pw"))))
    $pw = $null
    Ok 'Created the internal Signal login'
  }

  if ((Test-Path secrets\tunnel_token) -and (Yes-No 'A tunnel token is already saved. Keep it?' 'y')) { Ok 'Kept tunnel token'; return }
  Say 'Paste the Cloudflare Tunnel token (or the whole install command Cloudflare shows).'
  Say "Paste with a right-click or Ctrl+V. Only * symbols will show. Press Enter when done."
  while ($true) {
    $raw = Ask-Secret 'Tunnel token'
    $tok = ($raw -split '\s+' | Where-Object { $_ -match '^eyJ[A-Za-z0-9+/_=-]{40,}$' } | Select-Object -Last 1)
    $raw = $null
    if ($tok) { break }
    Warn "That wasn't a tunnel token. It is one long line starting with eyJ. Try again."
  }
  Write-Secret 'tunnel_token' (Text-Bytes $tok); $tok = $null
  Ok 'Saved the tunnel token'
}

function Build-Gate {
  Step '4/6  Building the password gate (first time: a few minutes)'
  & docker compose build signal-gate
  if ($LASTEXITCODE -ne 0) { Stop-Setup 'The build failed. Check your internet connection and run setup again.' }
  Ok 'Built signal-web-gate:local'
}

function Get-Hash([string]$password) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = (Get-Command docker).Source
  $psi.Arguments = 'run --rm -i --network none signal-web-gate:local -hash-stdin'
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  # Write the password with no trailing newline (the gate refuses one).
  $bytes = Text-Bytes $password
  $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
  $p.StandardInput.Close()
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  if ($p.ExitCode -ne 0) { Stop-Setup "Hashing failed: $err" }
  return $out.Trim()
}

function Set-Password([bool]$force) {
  Step '5/6  Your gate password'
  if ((Test-Path secrets\gate_password.argon2) -and -not $force) {
    Ok 'A password is already set (to change it, run setup with -ResetPassword)'; return
  }
  $null = & docker image inspect signal-web-gate:local 2>$null
  if ($LASTEXITCODE -ne 0) { Build-Gate }
  Say 'Choose a password for the dark Signal password page. Use at least 12 characters.'
  Say 'Only * symbols will show. Store it in a password manager.'
  while ($true) {
    $pw = Ask-Secret 'New gate password'
    $pw2 = Ask-Secret 'Type it again'
    if ($pw -cne $pw2) { Warn "They didn't match. Try again."; continue }
    if ($pw.Length -lt 12) { Warn 'Too short. Use 12 or more characters.'; continue }
    break
  }
  $hash = Get-Hash $pw
  $pw = $null; $pw2 = $null
  if (-not $hash.StartsWith('$argon2id$')) { Stop-Setup 'Unexpected hash output.' }
  Write-Secret 'gate_password.argon2' (Text-Bytes "$hash`n"); $hash = $null
  Ok 'Saved the password as an argon2id hash'
}

function Start-Stack {
  Step '6/6  Starting Signal'
  & docker compose up -d
  if ($LASTEXITCODE -ne 0) { Stop-Setup "Docker couldn't start the stack. See the walkthrough's troubleshooting." }
  Say 'Waiting for the gate to report healthy (up to 3 minutes)...'
  $id = (& docker compose ps -q signal-gate)
  $status = 'missing'
  for ($i = 0; $i -lt 36; $i++) {
    $status = (& docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $id 2>$null)
    if ($status -eq 'healthy') { break }
    Start-Sleep -Seconds 5
  }
  if ($status -eq 'healthy') { Ok 'Password gate is healthy' }
  else { Warn "The gate isn't healthy yet (status: $status). Recent gate log:"; & docker compose logs --tail 15 signal-gate }
  $tunnelLog = (& docker compose logs signal-tunnel 2>$null | Out-String)
  if ($tunnelLog -match 'Registered tunnel connection') { Ok 'Cloudflare Tunnel is connected' }
  else {
    Warn "The tunnel hasn't connected yet. If this stays, check the token. Recent tunnel log:"
    (& docker compose logs --tail 10 signal-tunnel 2>$null) | ForEach-Object { $_ -replace 'eyJ[A-Za-z0-9+/_=-]+', '[token hidden]' }
  }
  Write-Host ''
  Write-Host ("All set. Open {0} in your browser." -f (Get-EnvValue 'GATE_ORIGIN')) -ForegroundColor Green
  Say 'Sign in with the emailed code, enter your gate password, then scan the QR code'
  Say 'with Signal on your phone (Settings > Linked devices).'
  Say 'The first start can take a minute or two before Signal appears.'
}

Write-Host 'Signal web gate setup  (press Ctrl+C at any time to stop; it is safe to run again)' -ForegroundColor Cyan
Test-Docker
if ($ResetPassword) {
  if (-not (Test-Path .env)) { Stop-Setup 'Run the full setup first.' }
  Set-Password $true
  # A new session key signs out every browser that used the old password.
  Write-Secret 'session_key' (Random-Bytes 32)
  & docker compose restart signal-gate
  Ok 'Password changed. Every browser is signed out and needs the new password.'
  exit 0
}
Set-Settings
New-Secrets
Build-Gate
Set-Password $false
Start-Stack
