using System.Diagnostics;
using CadmusVulnApp.Data;

namespace CadmusVulnApp.Endpoints;

/// <summary>
/// A05:2025 - Injection  (down from #3, 38 CWEs)
///
/// Still the most-tested category, with more CVEs mapped to it than any other,
/// but it drops two places because the industry has largely tooled its way to
/// parameterised queries and auto-escaping template engines. OWASP groups a
/// wide range here: XSS (high frequency, low impact) through to SQL injection
/// (low frequency, high impact).
///
/// One root cause, four faces: data crossing a parser boundary while still
/// carrying the ability to be read as code.
/// </summary>
public static class A05_Injection
{
    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api/a05").WithTags("A05 Injection");

        // ------------------------------------------------------------------
        // >>> VULN A05 : CWE-89 : SQL injection by string concatenation.
        //     The classic. SonarQube rule S3649 and Snyk Code both flag this
        //     on a taint path from the query string to ExecuteReader.
        //
        //     Demonstrate in CR1 with sqlmap (already on VM1):
        //       sqlmap -u "http://localhost:5080/api/a05/search?customer=x" --batch
        // ------------------------------------------------------------------
        g.MapGet("/search", (string customer) =>
        {
            using var cn = AppDatabase.Open();
            using var cmd = cn.CreateCommand();

            cmd.CommandText =
                "SELECT Id, Customer, AmountEur FROM Invoices WHERE Customer LIKE '%" +
                customer + "%'";

            var results = new List<object>();
            using var r = cmd.ExecuteReader();
            while (r.Read())
                results.Add(new { Id = r.GetInt32(0), Customer = r.GetString(1), Amount = r.GetDouble(2) });

            return Results.Ok(results);
        });


        // ------------------------------------------------------------------
        // >>> VULN A05 : CWE-79 : reflected cross-site scripting. User input is
        //     interpolated into an HTML response with no contextual encoding,
        //     and the response is served as text/html. No CSP is set (see A02),
        //     so nothing contains it.
        // ------------------------------------------------------------------
        g.MapGet("/greet", (string name) =>
        {
            var html = $"""
                <!doctype html>
                <html><body>
                  <h1>Welcome back, {name}</h1>
                  <p>Your last sign-in was today.</p>
                </body></html>
                """;
            return Results.Content(html, "text/html");
        });


        // ------------------------------------------------------------------
        // >>> VULN A05 : CWE-78 : OS command injection. Caller-controlled text
        //     lands in a shell argument string, so ; && | and $() all work.
        // ------------------------------------------------------------------
        g.MapGet("/ping", (string host) =>
        {
            var psi = new ProcessStartInfo
            {
                FileName = OperatingSystem.IsWindows() ? "cmd.exe" : "/bin/sh",
                Arguments = OperatingSystem.IsWindows() ? $"/c ping -n 1 {host}" : $"-c \"ping -c 1 {host}\"",
                RedirectStandardOutput = true,
                UseShellExecute = false
            };

            using var proc = Process.Start(psi);
            var output = proc!.StandardOutput.ReadToEnd();
            proc.WaitForExit();
            return Results.Text(output);
        });


        // ------------------------------------------------------------------
        // >>> VULN A05 : CWE-22 : path traversal. The caller's string is joined
        //     onto a base directory, and ../ walks straight out of it.
        // ------------------------------------------------------------------
        g.MapGet("/report", (string file) =>
        {
            var baseDir = Path.Combine(AppContext.BaseDirectory, "reports");
            var full = Path.Combine(baseDir, file);
            if (!File.Exists(full)) return Results.NotFound();
            return Results.Text(File.ReadAllText(full));
        });

    }
}
