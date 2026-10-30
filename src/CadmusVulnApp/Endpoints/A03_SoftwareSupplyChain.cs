using Newtonsoft.Json;

namespace CadmusVulnApp.Endpoints;

/// <summary>
/// A03:2025 - Software Supply Chain Failures  (NEW, 5 CWEs)
///
/// An expansion of A06:2021 "Vulnerable and Outdated Components" to cover the
/// whole ecosystem: dependencies, build systems and distribution infrastructure.
/// It was voted in overwhelmingly by the community survey rather than promoted
/// by the data. OWASP's own note is the striking one for N1: this category has
/// the *fewest* occurrences in the dataset but the *highest* average exploit
/// and impact scores of any category. Rare, and devastating when it lands.
///
/// The defects here are mostly NOT in this file. They are in:
///   CadmusVulnApp.csproj   - four advisory-bearing packages, NuGetAudit off,
///                            no lock file, restore warnings suppressed
///   Dockerfile             - unpinned :latest base image, curl | bash install
///   .github/workflows/     - unpinned third-party actions on mutable tags
///
/// That is the lesson: a supply-chain review reads manifests and pipelines,
/// not just source code.
/// </summary>
public static class A03_SoftwareSupplyChain
{
    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api/a03").WithTags("A03 Software Supply Chain");

        // ------------------------------------------------------------------
        // >>> VULN A03 : CWE-1104 : use of an unmaintained third-party
        //     component. Newtonsoft.Json 9.0.1 dates from 2016 and predates
        //     every deserialisation hardening added since. It is still doing
        //     load-bearing work in a request path.
        // ------------------------------------------------------------------
        g.MapPost("/import", (HttpRequest req) =>
        {
            using var reader = new StreamReader(req.Body);
            var raw = reader.ReadToEnd();
            var parsed = JsonConvert.DeserializeObject(raw);
            return Results.Ok(new { imported = true, echo = parsed });
        });


        // ------------------------------------------------------------------
        // >>> VULN A03 : CWE-494 : code downloaded and executed without an
        //     integrity check. The "plugin catalogue" is fetched over plain
        //     HTTP from a mutable URL with no signature and no checksum.
        // ------------------------------------------------------------------
        g.MapGet("/plugins/refresh", async (IHttpClientFactory factory) =>
        {
            var http = factory.CreateClient();
            var manifest = await http.GetStringAsync(
                "http://plugins.cadmus-range.local/catalogue.json");

            var target = Path.Combine(AppContext.BaseDirectory, "plugins", "catalogue.json");
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            await File.WriteAllTextAsync(target, manifest);

            return Results.Ok(new { refreshed = true, bytes = manifest.Length });
        });


        // ------------------------------------------------------------------
        //  CR3 lab starting point - the commands trainees run against this
        //  project. Left here as documentation, not executed.
        //
        //    dotnet list package --vulnerable --include-transitive
        //    dotnet list package --deprecated
        //    dotnet list package --outdated
        //    snyk test --file=src/CadmusVulnApp/CadmusVulnApp.csproj
        //
        //  Generate an SBOM and diff it before and after remediation:
        //    dotnet tool install --global CycloneDX
        //    dotnet CycloneDX src/CadmusVulnApp/CadmusVulnApp.csproj -o sbom/
        //
        //  Then re-enable the build-time controls disabled in the .csproj:
        //    <NuGetAudit>true</NuGetAudit>
        //    <NuGetAuditMode>all</NuGetAuditMode>
        //    <NuGetAuditLevel>low</NuGetAuditLevel>
        //    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
        //    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
        //  and remove NU1901-NU1904 from <NoWarn>.
        // ------------------------------------------------------------------
    }
}
