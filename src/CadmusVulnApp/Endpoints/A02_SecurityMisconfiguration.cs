namespace CadmusVulnApp.Endpoints;

/// <summary>
/// A02:2025 - Security Misconfiguration  (up from #5, 16 CWEs, 3.00% incidence)
///
/// The biggest mover in the 2025 list. OWASP's stated reason: an ever larger
/// share of application behaviour is now expressed as configuration rather
/// than code, so the configuration surface is where the defects migrated.
///
/// Most of this category lives in Program.cs and appsettings.json rather than
/// in handlers - which is exactly the N1 teaching point. A code review that
/// only reads .cs files will miss every one of them.
/// </summary>
public static class A02_SecurityMisconfiguration
{
    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api/a02").WithTags("A02 Security Misconfiguration");

        g.MapGet("/debug/config", (IConfiguration config) =>
        {
            var dump = config.AsEnumerable()
                             .Where(kv => kv.Value is not null)
                             .ToDictionary(kv => kv.Key, kv => kv.Value);
            return Results.Ok(dump);
        });


        g.MapGet("/version", () => Results.Ok(new
        {
            Runtime = Environment.Version.ToString(),
            Os = Environment.OSVersion.ToString(),
            Host = Environment.MachineName,
            Newtonsoft = "9.0.1",
            ImageSharp = "1.0.2",
            BuildPath = AppContext.BaseDirectory
        }));


        g.MapMethods("/echo", new[] { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS" },
            (HttpContext ctx) => Results.Ok(new
            {
                Method = ctx.Request.Method,
                Headers = ctx.Request.Headers
                              .ToDictionary(h => h.Key, h => h.Value.ToString())
            }));


        // ------------------------------------------------------------------
        //  Discussion anchor for N1 - not itself an endpoint.
        //
        //  Other A02 defects deliberately planted elsewhere in this project:
        //    Program.cs         UseDeveloperExceptionPage() unconditionally
        //    Program.cs         UseDirectoryBrowser() over wwwroot
        //    Program.cs         no security headers, no HSTS, no HTTPS redirect
        //    Program.cs         session cookie not HttpOnly / not Secure
        //    Program.cs         Swagger exposed in every environment
        //    AppDatabase.cs     default admin/admin123 account seeded
        //    appsettings.json   secrets committed to source control
        //    Dockerfile         container runs as root
        //
        //  Ask the room: which of these would a SAST tool find, which needs a
        //  DAST scan, and which is only visible to someone reading the
        //  deployment manifest? That split is the point of the CR1 lab.
        // ------------------------------------------------------------------
    }
}
