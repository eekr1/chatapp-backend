[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$SecretSource)
$ErrorActionPreference = 'Stop'
$root = 'C:\TalkX'
if (Get-Service TalkXBackend -ErrorAction SilentlyContinue) { throw 'Existing TalkX service: inspect before installing.' }
if (-not (Test-Path -LiteralPath $SecretSource -PathType Leaf)) { throw 'Missing Render environment export.' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$sha = (& git -C $repo rev-parse HEAD).Trim()
if ($sha -notmatch '^[a-f0-9]{40}$') { throw 'Invalid release SHA.' }
if ((& git -C $repo status --porcelain)) { throw 'Commit and verify release before installing.' }
foreach ($folder in @('bin','ops','logs','secrets','releases')) { New-Item -ItemType Directory -Path (Join-Path $root $folder) -Force | Out-Null }
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'ACL setup failed.' }
& icacls.exe "$root\logs" /grant '*S-1-5-19:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Log ACL setup failed.' }
Copy-Item -LiteralPath $SecretSource -Destination "$root\secrets\backend.env"
$release = Join-Path "$root\releases" $sha
& git clone --no-hardlinks $repo $release
if ($LASTEXITCODE -ne 0) { throw 'Release clone failed.' }
& git -C $release checkout --detach $sha
if ($LASTEXITCODE -ne 0) { throw 'Release checkout failed.' }
Push-Location $release
try { & npm.cmd ci --omit=dev; if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' } } finally { Pop-Location }
Copy-Item -LiteralPath "$PSScriptRoot\launch.cjs" -Destination "$root\ops\launch.cjs"
Copy-Item -LiteralPath "$PSScriptRoot\TalkXBackend.xml" -Destination "$root\bin\TalkXBackend.xml"
[IO.File]::WriteAllText("$root\active-release.txt", $sha)
& curl.exe -fL --max-time 60 https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe -o "$root\bin\TalkXBackend.exe"
if ($LASTEXITCODE -ne 0) { throw 'WinSW download failed.' }
& curl.exe -fL --max-time 60 https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe -o "$root\bin\cloudflared.exe"
if ($LASTEXITCODE -ne 0) { throw 'Cloudflared download failed.' }
& "$root\bin\TalkXBackend.exe" install
if ($LASTEXITCODE -ne 0) { throw 'Service installation failed.' }
# Keep stopped and manual until Tunnel, backup, and cutover checks are complete.
Set-Service TalkXBackend -StartupType Manual
Get-Service TalkXBackend | Select-Object Name, Status, StartType
Write-Output "Prepared release $sha; service installed but not started."
