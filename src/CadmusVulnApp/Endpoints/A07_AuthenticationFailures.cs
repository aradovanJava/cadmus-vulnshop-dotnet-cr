using System.Text;
using System.Text.Json;
using CadmusVulnApp.Data;

namespace CadmusVulnApp.Endpoints;

/// <summary>
/// A07:2025 - Authentication Failures  (holds at #7, 36 CWEs)
///
/// Renamed from "Identification and Authentication Failures" in 2021. OWASP
/// notes it stayed put largely because standardised frameworks have absorbed
/// the hard parts - which is itself the lesson: the applications still failing
/// here are the ones that hand-rolled it, exactly as this module does.
/// </summary>
public static class A07_AuthenticationFailures
{
    // >>> VULN A07 : CWE-321 : hard-coded token signing secret, and a weak one.
    private const string JwtSecret = "cadmus";

    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api/a07").WithTags("A07 Authentication Failures");

        // ------------------------------------------------------------------
        // >>> VULN A07 : CWE-307 : no account lockout, no throttling, no
        //     back-off. FailedLogins is counted and then ignored.
        // >>> VULN A07 : CWE-521 : no password policy - 'trainee' is a valid
        //     seeded password.
        // >>> VULN A07 : CWE-384 : session fixation. The session id present
        //     before authentication is kept afterwards, so an attacker who
        //     plants a known session id keeps a valid authenticated session.
        // ------------------------------------------------------------------
        g.MapPost("/login", (LoginRequest req, HttpContext ctx) =>
        {
            using var cn = AppDatabase.Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "SELECT Id, Role, PasswordHash FROM Users WHERE Username = $u";
            cmd.Parameters.AddWithValue("$u", req.Username ?? "");

            using var r = cmd.ExecuteReader();
            if (!r.Read())
                // >>> VULN A07 : CWE-204 : distinguishable responses turn this
                //                into a username oracle.
                return Results.BadRequest(new { error = "No such user" });

            var id = r.GetInt32(0);
            var role = r.GetString(1);
            var stored = r.GetString(2);
            r.Close();

            if (stored != AppDatabase.LegacyHash(req.Password ?? ""))
            {
                using var bump = cn.CreateCommand();
                bump.CommandText = "UPDATE Users SET FailedLogins = FailedLogins + 1 WHERE Id = $id";
                bump.Parameters.AddWithValue("$id", id);
                bump.ExecuteNonQuery();
                return Results.BadRequest(new { error = "Wrong password" });
            }

            ctx.Session.SetInt32("uid", id);
            ctx.Session.SetString("role", role);

            return Results.Ok(new { token = IssueToken(id, role), role });
        });


        // ------------------------------------------------------------------
        // >>> VULN A07 : CWE-347 : the token's signature is never verified.
        //     The handler base64-decodes the payload and believes it. Anyone
        //     can mint a token claiming role=Administrator.
        // ------------------------------------------------------------------
        g.MapGet("/whoami", (HttpContext ctx) =>
        {
            var header = ctx.Request.Headers.Authorization.ToString();
            if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return Results.Unauthorized();

            var token = header["Bearer ".Length..];
            var parts = token.Split('.');
            if (parts.Length < 2) return Results.Unauthorized();

            var json = Encoding.UTF8.GetString(FromBase64Url(parts[1]));
            var claims = JsonSerializer.Deserialize<Dictionary<string, object>>(json);

            return Results.Ok(new { claims, verified = false });
        });


        // ------------------------------------------------------------------
        // >>> VULN A07 : CWE-640 + CWE-330 : password reset token generated
        //     from a clock-seeded PRNG, with no expiry and no single-use flag.
        //     Predict the seed, predict every reset token in the system.
        // ------------------------------------------------------------------
        g.MapPost("/request-reset", (string username) =>
        {
            var token = new Random(Environment.TickCount).Next(100000, 999999).ToString();

            using var cn = AppDatabase.Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "UPDATE Users SET ResetToken = $t WHERE Username = $u";
            cmd.Parameters.AddWithValue("$t", token);
            cmd.Parameters.AddWithValue("$u", username);
            cmd.ExecuteNonQuery();

            // >>> VULN A07 : and the token is returned in the HTTP response
            //                instead of being sent out-of-band, so possession
            //                of the reset channel proves nothing at all.
            return Results.Ok(new { username, resetToken = token });
        });


        // ------------------------------------------------------------------
        // >>> VULN A07 : CWE-598 : credentials accepted in the query string,
        //     where they land in access logs, proxy logs, browser history and
        //     the Referer header of every outbound link.
        // ------------------------------------------------------------------
        g.MapGet("/quick-login", (string user, string pass) =>
            Results.Ok(new { authenticated = true, user }));

    }

    private static string IssueToken(int userId, string role)
    {
        var header = ToBase64Url("""{"alg":"HS256","typ":"JWT"}"""u8.ToArray());
        var payload = ToBase64Url(Encoding.UTF8.GetBytes(
            $$"""{"sub":"{{userId}}","role":"{{role}}"}"""));
        // Signature is computed but, per the /whoami defect above, never checked.
        var sig = ToBase64Url(Encoding.UTF8.GetBytes(JwtSecret));
        return $"{header}.{payload}.{sig}";
    }

    private static string ToBase64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
        return Convert.FromBase64String(s);
    }

    public record LoginRequest(string Username, string Password);
}
