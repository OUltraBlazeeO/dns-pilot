param([string]$Python = "python", [switch]$SkipInstall)
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
function Run([string]$Exe, [string[]]$ArgList) {
    & $Exe @ArgList
    if ($LASTEXITCODE -ne 0) { throw "Команда завершилась с кодом $LASTEXITCODE" }
}
if (!(Test-Path ".venv/Scripts/python.exe")) {
    Run $Python @("-m","venv",".venv")
}
$exe = (Resolve-Path ".venv/Scripts/python.exe").Path
Run $exe @("-c","import sys, struct; assert sys.version_info >= (3,12) and struct.calcsize('P') == 8, 'Requires Python 3.12+ x64'")
if (!$SkipInstall) { Run $exe @("-m","pip","install","-r","requirements-dev.txt") }
Run $exe @("tools/icon.py")
Run $exe @("-m","pytest","-q")
Run $exe @("-m","PyInstaller","--noconfirm","DNSPilot.spec")
$smoke = Start-Process -FilePath (Resolve-Path "dist/DNS Pilot.exe").Path -ArgumentList "--self-test" -Wait -PassThru -WindowStyle Hidden
if ($smoke.ExitCode -ne 0) { throw "Ошибка самопроверки EXE: $($smoke.ExitCode)" }
Get-FileHash -LiteralPath "dist/DNS Pilot.exe" -Algorithm SHA256
