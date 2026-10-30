using CadmusVulnApp.Data;

namespace CadmusVulnApp.Endpoints;

/// <summary>
/// A09:2025 - Security Logging &amp; Alerting Failures  (holds at #9, 5 CWEs)
///
/// Renamed for 2025 from "Logging and Monitoring". OWASP's justification is
/// worth quoting almost verbatim in the deck: great logging with no alerting is
/// of minimal value in identifying security incidents. The category was voted
/// in by the community survey - it will always be under-represented in scan
/// data, because no scanner can detect the absence of a response.
///
/// This is the category that decides how long every other category goes
/// unnoticed. Mean time to detect is a design output, not an operations
/// accident.
/// </summary>
public static class A09_LoggingAndAlerting
{
    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api/a09").WithTags("A09 Logging & Alerting");

        g.MapPost("/admin/delete-user", (int id, HttpContext ctx) =>
        {
            var role = ctx.Session.GetString("role");
            if (role != "Administrator")
                return Results.Forbid();   // silent denial - no record kept

            using var cn = AppDatabase.Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "DELETE FROM Users WHERE Id = $id";
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();

            return Results.Ok();          // and the success is not recorded either
        });


        g.MapPost("/audit", (AuditEvent e, ILogger<Program> logger) =>
        {
            logger.LogError(
                "AUDIT user={User} password={Password} token={Token} iban={Iban} note={Note}",
                e.User, e.Password, e.Token, e.Iban, e.Note);

            return Results.Ok(new { logged = true });
        });


        g.MapGet("/note", (string note, ILogger<Program> logger) =>
        {
            logger.LogError("User note: " + note);   // string concatenation, not a template
            return Results.Ok(new { noted = true });
        });


        // ------------------------------------------------------------------
        //  Compounding defect, set in Program.cs:
        //    builder.Logging.SetMinimumLevel(LogLevel.Error);
        //  Every LogInformation and LogWarning in the application is discarded
        //  before it reaches a sink. The A07 brute-force attempts therefore
        //  leave no trace whatsoever.
        //
        //  N1 discussion prompt: the team that wrote this had a logging
        //  framework, a log aggregator and a retention policy. Which of the
        //  three things you actually need for detection did they have?
        //  (Signal, storage, response. They had storage.)
        // ------------------------------------------------------------------
    }

    public record AuditEvent(string User, string Password, string Token, string Iban, string Note);
}
