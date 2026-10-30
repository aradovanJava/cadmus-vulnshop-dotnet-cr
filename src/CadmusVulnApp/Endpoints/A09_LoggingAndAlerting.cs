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

        // ------------------------------------------------------------------
        // >>> VULN A09 : CWE-778 : a security-relevant event - a failed
        //     privileged action - produces no log record at all. There is
        //     nothing to alert on, nothing to correlate, and nothing to hand
        //     an incident responder afterwards.
        // ------------------------------------------------------------------
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


        // ------------------------------------------------------------------
        // >>> VULN A09 : CWE-532 : the opposite failure - logging that captures
        //     exactly what must never be written down. The password, the token
        //     and the IBAN all land in plaintext in a log that is retained for
        //     a year and read by people with no need to see any of it.
        // ------------------------------------------------------------------
        g.MapPost("/audit", (AuditEvent e, ILogger<Program> logger) =>
        {
            logger.LogError(
                "AUDIT user={User} password={Password} token={Token} iban={Iban} note={Note}",
                e.User, e.Password, e.Token, e.Iban, e.Note);

            return Results.Ok(new { logged = true });
        });


        // ------------------------------------------------------------------
        // >>> VULN A09 : CWE-117 : log injection. Unsanitised input containing
        //     CR/LF is written straight into a line-oriented log, so an
        //     attacker forges whole log entries and can bury the real ones.
        //
        //     Try: note=ok%0d%0aAUDIT%20user%3Dadmin%20outcome%3Dsuccess
        // ------------------------------------------------------------------
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
