[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit, [string]$ExternalUrl)
$ErrorActionPreference = 'Stop'
$root = 'C:\TalkX'
$release = Join-Path "$root\releases" $Commit
if (-not (Test-Path "$release\index.js")) { throw 'Prepare the immutable release first.' }
if (-not (Test-Path "$release\node_modules\ws")) { throw 'Install locked production dependencies first.' }
$previous = (Get-Content -LiteralPath "$root\active-release.txt" -Raw).Trim()
if ($previous -notmatch '^[a-f0-9]{40}$') { throw 'Invalid rollback release.' }
function Wait-Ready([string]$Expected) {
    for ($attempt = 0; $attempt -lt 15; $attempt++) {
        try {
            $r = Invoke-RestMethod 'http://127.0.0.1:3000/health/ready' -TimeoutSec 5
            if ($r.status -eq 'ready' -and $r.commitSha -eq $Expected) { return }
        } catch { }
        Start-Sleep -Seconds 2
    }
    throw 'Readiness timeout or wrong commit.'
}
try {
    Stop-Service TalkXBackend
    [IO.File]::WriteAllText("$root\active-release.txt", $Commit)
    Start-Service TalkXBackend
    Wait-Ready $Commit
    & 'C:\Program Files\nodejs\node.exe' "$release\ops\windows\smoke.cjs" 'http://127.0.0.1:3000'
    if ($LASTEXITCODE -ne 0) { throw 'Local HTTP/CORS/WS smoke failed.' }
    if ($ExternalUrl) {
        & 'C:\Program Files\nodejs\node.exe' "$release\ops\windows\smoke.cjs" $ExternalUrl
        if ($LASTEXITCODE -ne 0) { throw 'External HTTP/CORS/WS smoke failed.' }
    }
    Set-Service TalkXBackend -StartupType Automatic
    Write-Output "Deployment healthy: $Commit"
} catch {
    Stop-Service TalkXBackend -ErrorAction SilentlyContinue
    [IO.File]::WriteAllText("$root\active-release.txt", $previous)
    Start-Service TalkXBackend
    Wait-Ready $previous
    throw "Deployment failed; restored $previous. Inspect service logs."
}
