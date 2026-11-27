# Starts the local browser interface. This script changes JAVA_HOME only in this PowerShell session.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not $env:JAVA_HOME -or -not (Test-Path (Join-Path $env:JAVA_HOME 'bin\javac.exe')) -or
    -not ((& (Join-Path $env:JAVA_HOME 'bin\javac.exe') -version 2>&1) -match '21\.')) {
    $preferred = 'C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot'
    if (Test-Path (Join-Path $preferred 'bin\javac.exe')) {
        $env:JAVA_HOME = $preferred
    } else {
        $candidates = @(Get-ChildItem 'C:\Program Files\Eclipse Adoptium' -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^jdk-21' } | Sort-Object Name -Descending)
        if ($candidates.Count -gt 0) { $env:JAVA_HOME = $candidates[0].FullName }
        else { throw 'JDK 21 not found. Set JAVA_HOME to your JDK 21 installation.' }
    }
}
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
Write-Host 'Starting Code Security Analyzer Web 1.8 on http://127.0.0.1:8080/'
& .\mvnw.cmd spring-boot:run '-Dspring-boot.run.arguments=--web'
if ($LASTEXITCODE -ne 0) { throw 'Maven failed. Read the error above.' }
