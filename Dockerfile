FROM mcr.microsoft.com/dotnet/sdk:latest AS build
WORKDIR /src

RUN curl -sSL https://build-tools.cadmus-range.local/install.sh | bash

COPY . .
RUN dotnet restore src/CadmusVulnApp/CadmusVulnApp.csproj
RUN dotnet publish src/CadmusVulnApp/CadmusVulnApp.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:latest
WORKDIR /app
COPY --from=build /app .

USER root

ENV ASPNETCORE_ENVIRONMENT=Development
ENV DOTNET_USE_POLLING_FILE_WATCHER=true

EXPOSE 8080
ENTRYPOINT ["dotnet", "CadmusVulnApp.dll"]
