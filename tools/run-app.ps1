# CADMUS-CR-13 - build and run the vulnerable application (SC1).
#
#   powershell -ExecutionPolicy Bypass -File C:\Lab\cadmus-vulnshop-dotnet-cr\tools\run-app.ps1
#
# Binds to 127.0.0.1:5080 only. The sandbox forwards sc1:5080 to it so OWASP
# ZAP on OWZ1 can reach it; nothing else can. Do not change the address.
# Stop it with Ctrl+C.

Set-Location (Join-Path $PSScriptRoot '..')

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Host "dotnet was not found on PATH - run C:\Lab\verify-cr-env.ps1 and tell your instructor." -ForegroundColor Red
    exit 1
}

Write-Host "Starting CADMUS-CR-13 VulnShop on http://127.0.0.1:5080  (Swagger: /swagger, Ctrl+C to stop)" -ForegroundColor Green
dotnet run --project src\CadmusVulnApp --no-launch-profile --urls http://127.0.0.1:5080
