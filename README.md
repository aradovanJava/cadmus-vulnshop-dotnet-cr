# cadmus-vulnshop-dotnet-cr

The Cyber Range training target for **CADMUS-CR-13 — Secure Coding .NET/C#**
(BTCMP-02 Secure Coding, levels A1–E1).

> ## ⚠ TRAINING ARTEFACT — DO NOT DEPLOY
>
> This application contains **intentional, exploitable security defects** in
> all ten OWASP Top 10:2025 categories, including a working OS command
> injection. It exists to be scanned, discussed and repaired inside the
> CADMUS Cyber Range sandbox. **Read [SAFETY.md](SAFETY.md) before you start it.**

This is the **participant build**: the remediation guidance that accompanies
each defect in the instructor copy has been removed, and so has the reference
CI/CD pipeline. Working those out is the exercise.

---

## In the Cyber Range sandbox (SC1)

The repository is already cloned to `C:\Lab\cadmus-vulnshop-dotnet-cr` and
built once during provisioning.

| Task | Command (PowerShell on SC1) |
|---|---|
| Run the app | `powershell -ExecutionPolicy Bypass -File C:\Lab\cadmus-vulnshop-dotnet-cr\tools\run-app.ps1` |
| Static scan (SonarQube) | `powershell -ExecutionPolicy Bypass -File C:\Lab\cadmus-vulnshop-dotnet-cr\tools\scan-sonar.ps1 -Token <token>` |
| Dependency scan (Snyk) | `snyk auth` once, then `snyk test --file=src\CadmusVulnApp\CadmusVulnApp.csproj` |
| Build a release | `dotnet publish src\CadmusVulnApp\CadmusVulnApp.csproj -c Release -o publish` |

| Endpoint | URL |
|---|---|
| Swagger UI (on SC1) | <http://127.0.0.1:5080/swagger> |
| OpenAPI definition, as OWASP ZAP on OWZ1 reaches it | `http://sc1:5080/swagger/v1/swagger.json` |
| Health | <http://127.0.0.1:5080/health> |

The app binds to `127.0.0.1:5080` only. The sandbox forwards `sc1:5080` to it
for the ZAP machine (OWZ1) and nothing else. The SQLite database
(`cadmus-range.db`) is created and seeded on first start; delete it to reset.

## Anywhere else

Only on an isolated machine you are prepared to treat as compromised:

```bash
dotnet run --project src/CadmusVulnApp --no-launch-profile --urls http://127.0.0.1:5080
```

Requires the **.NET 10 SDK**.

---

## Layout

```
src/CadmusVulnApp/
  Program.cs                 startup, middleware, cookies, CORS, logging
  Endpoints/A01_*.cs … A10_*.cs   one module per OWASP Top 10:2025 category
  Data/AppDatabase.cs        SQLite store and seeding
  appsettings.json           configuration
  wwwroot/                   static files
Dockerfile, docker-compose.yml   container build (itself part of the exercise)
.github/workflows/01-starter-build.yml   the pipeline you extend in level E1
.zap/rules.tsv               ZAP baseline rule tuning you can start from in E1
tools/                       run and scan helpers for the sandbox
```

## What each level uses

| Level | What you do with this repository |
|---|---|
| A1–A2 · DAST | Run the app; scan it with OWASP ZAP via its OpenAPI definition |
| A3–A4 · SAST | Scan the source with SonarQube (`tools\scan-sonar.ps1`) |
| C1 | Triage the findings against OWASP Top 10:2025 |
| C2 | Fix the most serious weakness in the source and prove it by rescanning |
| D1 | Commit the fix on a branch and build a release |
| E1 | In **your own fork**, extend `.github/workflows/01-starter-build.yml` so a build fails when the security bar is not met |

## For the debrief

Which tool class realistically finds each category — the most useful thing on
this page *after* you have done the work:

| Category | Found by |
|---|---|
| **A01** Broken Access Control | SAST partial, DAST partial, **manual** |
| **A02** Security Misconfiguration | **DAST**, IaC scan |
| **A03** Software Supply Chain Failures | **SCA**, not SAST |
| **A04** Cryptographic Failures | **SAST** |
| **A05** Injection | **SAST + DAST** |
| **A06** Insecure Design | **manual / threat modelling only** |
| **A07** Authentication Failures | SAST partial, **manual** |
| **A08** Software or Data Integrity Failures | **SAST**, DAST for the SRI defect |
| **A09** Security Logging & Alerting Failures | **neither — absence is undetectable** |
| **A10** Mishandling of Exceptional Conditions | SAST partial, **DAST** for trace leakage |

---

Produced for the CADMUS project under Grant Agreement No. 101190006, supported
by the European Health and Digital Executive Agency (HaDEA). Views and opinions
expressed are those of the author(s) only and do not necessarily reflect those
of the European Union or HaDEA.

OWASP Top 10:2025 category names are taken from <https://owasp.org/Top10/2025/>,
© OWASP Foundation, CC BY 3.0.
