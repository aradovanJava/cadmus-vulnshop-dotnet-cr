using System.Reflection;
using System.Text;
using Newtonsoft.Json;

namespace CadmusVulnApp.Endpoints;

/// <summary>
/// A08:2025 - Software or Data Integrity Failures  (holds at #8)
///
/// OWASP's 2025 framing draws a deliberate line between A08 and A03: A03 is
/// integrity failure at ecosystem scale (dependencies, build systems,
/// distribution), A08 is the same failure "at a lower level" - inside your own
/// trust boundaries, on your own code and data artefacts.
///
/// The unifying question: what did we accept without verifying who produced it?
/// </summary>
public static class A08_IntegrityFailures
{
    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api/a08").WithTags("A08 Integrity Failures");

        g.MapPost("/restore-state", (HttpRequest req) =>
        {
            using var reader = new StreamReader(req.Body);
            var raw = reader.ReadToEnd();

            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };
            var state = JsonConvert.DeserializeObject<object>(raw, settings);

            return Results.Ok(new { restored = true, type = state?.GetType().FullName });
        });


        g.MapPost("/load-plugin", (string assemblyPath, string typeName) =>
        {
            var asm = Assembly.LoadFrom(assemblyPath);
            var type = asm.GetType(typeName);
            var instance = Activator.CreateInstance(type!);
            var result = type!.GetMethod("Execute")?.Invoke(instance, null);
            return Results.Ok(new { loaded = asm.FullName, result });
        });


        g.MapPost("/self-update", async (IHttpClientFactory factory) =>
        {
            var http = factory.CreateClient();
            var bytes = await http.GetByteArrayAsync(
                "http://updates.cadmus-range.local/latest/CadmusVulnApp.dll");

            var target = Path.Combine(AppContext.BaseDirectory, "update-staging.dll");
            await File.WriteAllBytesAsync(target, bytes);

            return Results.Ok(new { staged = true, bytes = bytes.Length });
        });


        g.MapGet("/dashboard", () => Results.Content("""
            <!doctype html>
            <html>
            <head>
              <script src="https://cdn.example-analytics.net/tracker.js"></script>
              <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            </head>
            <body><h1>Range Dashboard</h1></body>
            </html>
            """, "text/html"));

    }
}
