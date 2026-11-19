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
if (!$SkipInstall) {
    $pyVersion = & $exe -c "import sys; print(sys.version_info[:2] == (3,14))"
    if ($pyVersion -eq 'True') {
        Run $exe @("-m","pip","install","--require-hashes","--only-binary=:all:","-r","requirements-win314.lock")
    } else { Run $exe @("-m","pip","install","-r","requirements-dev.txt") }
}
$version = & $exe -c "from app import VERSION; print(VERSION)"
$outputDir = "dist/$version"
Run $exe @("-m","ruff","check","--select","F,E9","app","main.py","tests","tools")
Run $exe @("-m","pip","check")
Run $exe @("-m","pytest","-q")
Run $exe @("-m","PyInstaller","--noconfirm","--distpath",$outputDir,"DNSPilot.spec")
$smoke = Start-Process -FilePath (Resolve-Path "$outputDir/DNS Pilot.exe").Path -ArgumentList "--self-test" -Wait -PassThru -WindowStyle Hidden
if ($smoke.ExitCode -ne 0) { throw "Ошибка самопроверки EXE: $($smoke.ExitCode)" }
$hash = (Get-FileHash -LiteralPath "$outputDir/DNS Pilot.exe" -Algorithm SHA256).Hash
[IO.File]::WriteAllText((Join-Path $PSScriptRoot "$outputDir/SHA256SUMS.txt"), "$hash  DNS Pilot.exe`n")
Copy-Item -LiteralPath "GUIDE.md","RELEASE-NOTES.md","MANUAL-TESTS.md" -Destination $outputDir
Write-Output "$outputDir/DNS Pilot.exe  $hash"
