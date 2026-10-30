# CADMUS-CR-13 - static analysis with SonarQube (SC1).
#
#   powershell -ExecutionPolicy Bypass -File C:\Lab\cadmus-vulnshop-dotnet-cr\tools\scan-sonar.ps1 -Token <token>
#
# Create the token in SonarQube (http://localhost:9000):
#   My Account -> Security -> Generate Token, type "Global Analysis Token".
#
# SonarScanner for .NET works in three steps: "begin" prepares the analysis,
# the build lets the C# analysers observe the compilation, and "end" uploads
# the results. The scan takes a few minutes - start reading code meanwhile.

param(
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$HostUrl = 'http://localhost:9000'
)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

$projectKey  = 'cadmus-cr-13'
$projectName = 'CADMUS-CR-13 VulnShop .NET'

dotnet sonarscanner begin /k:"$projectKey" /n:"$projectName" /d:sonar.host.url="$HostUrl" /d:sonar.token="$Token"
if ($LASTEXITCODE -ne 0) { Write-Host "sonarscanner begin failed." -ForegroundColor Red; exit 1 }

dotnet build src\CadmusVulnApp\CadmusVulnApp.csproj -c Release
if ($LASTEXITCODE -ne 0) { Write-Host "Build failed." -ForegroundColor Red; exit 1 }

dotnet sonarscanner end /d:sonar.token="$Token"
if ($LASTEXITCODE -ne 0) { Write-Host "sonarscanner end failed." -ForegroundColor Red; exit 1 }

Write-Host "`nDone. Open $HostUrl/dashboard?id=$projectKey" -ForegroundColor Green
