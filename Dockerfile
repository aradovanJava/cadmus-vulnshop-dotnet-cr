# =============================================================================
#  VULN A03 - Software Supply Chain Failures (build & distribution layer)
#  Every defect below is deliberate. Trainees repair this file in CR3.
# =============================================================================

# >>> VULN A03 : CWE-1357 : unpinned base image. ":latest" is mutable, so the
#                bytes you build today are not the bytes you built yesterday,
#                and the image cannot be reproduced or attested.
FROM mcr.microsoft.com/dotnet/sdk:latest AS build
WORKDIR /src

# >>> VULN A03 : CWE-494 : remote script piped straight into a shell, over a
#                mutable URL, with no checksum and no signature.
RUN curl -sSL https://build-tools.cadmus-range.local/install.sh | bash

COPY . .
# >>> VULN A03 : restore without --locked-mode, so the resolved graph can drift
RUN dotnet restore src/CadmusVulnApp/CadmusVulnApp.csproj
RUN dotnet publish src/CadmusVulnApp/CadmusVulnApp.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:latest
WORKDIR /app
COPY --from=build /app .

# >>> VULN A02 : CWE-250 : the container runs as root. A single RCE in the
#                application becomes root inside the container.
USER root

# >>> VULN A02 : development environment forced on in the shipped image
ENV ASPNETCORE_ENVIRONMENT=Development
ENV DOTNET_USE_POLLING_FILE_WATCHER=true

EXPOSE 8080
ENTRYPOINT ["dotnet", "CadmusVulnApp.dll"]
