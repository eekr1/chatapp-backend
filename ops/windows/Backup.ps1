# TalkX nightly encrypted database backup wrapper.
# Runs backup.cjs (next to this script) and appends all output to C:\TalkX\logs\backup-<date>.log.
# Secrets (DATABASE_URL, generated keys) never appear in command lines or logs.
$ErrorActionPreference = 'Stop'
$root = 'C:\TalkX'
$logDir = Join-Path $root 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir ("backup-{0:yyyyMMdd}.log" -f (Get-Date))
$script = Join-Path $PSScriptRoot 'backup.cjs'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { throw 'backup.cjs must sit next to Backup.ps1.' }
$node = 'C:\Program Files\nodejs\node.exe'
if (-not (Test-Path -LiteralPath $node)) { $node = 'node.exe' }
"=== backup start $(Get-Date -Format o) ===" | Out-File -FilePath $log -Append -Encoding utf8
& $node $script *>> $log
$exit = $LASTEXITCODE
"=== backup end exit=$exit $(Get-Date -Format o) ===" | Out-File -FilePath $log -Append -Encoding utf8
exit $exit