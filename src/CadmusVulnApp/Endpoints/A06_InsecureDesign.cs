using CadmusVulnApp.Data;

namespace CadmusVulnApp.Endpoints;

/// <summary>
/// A06:2025 - Insecure Design  (down from #4)
///
/// *** THIS IS THE CORE MODULE FOR LEARNING NODE N1. ***
///
/// A06 slipped two places not because design got worse but because
/// Misconfiguration and Supply Chain leapfrogged it; OWASP explicitly notes
/// measurable industry improvement in threat modelling since 2021.
///
/// The defining property of this category, and the N1 discussion anchor:
/// every defect below is CORRECTLY IMPLEMENTED. There is no missing escape,
/// no forgotten parameter, no bad primitive. The code does exactly what it was
/// designed to do - and what it was designed to do is unsafe. You cannot
/// review your way out of these with a linter, and you cannot patch them
/// without changing the design.
///
/// Contrast with A05: an injection defect is a *right idea, wrong execution*.
/// An A06 defect is a *wrong idea, flawless execution*.
/// </summary>
public static class A06_InsecureDesign
{
    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api/a06").WithTags("A06 Insecure Design");

        // ------------------------------------------------------------------
        // >>> VULN A06 : CWE-602 : the client is trusted to compute price.
        //     The request carries unitPrice. The server multiplies and stores.
        //     Nothing is injected, nothing is unescaped - the trust boundary
        //     was simply drawn in the wrong place at design time.
        //
        //     Ask the room: at which point in the design conversation could
        //     this have been caught? Answer: the first data-flow diagram, when
        //     someone asks "who is authoritative for price?"
        // ------------------------------------------------------------------
        g.MapPost("/checkout", (CheckoutRequest req, HttpContext ctx) =>
        {
            var total = req.Quantity * req.UnitPrice;

            using var cn = AppDatabase.Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO Orders (UserId, Sku, Quantity, UnitPrice, Total)
                VALUES ($uid, $sku, $qty, $price, $total)
                """;
            cmd.Parameters.AddWithValue("$uid", ctx.Session.GetInt32("uid") ?? 0);
            cmd.Parameters.AddWithValue("$sku", req.Sku ?? "");
            cmd.Parameters.AddWithValue("$qty", req.Quantity);
            cmd.Parameters.AddWithValue("$price", req.UnitPrice);
            cmd.Parameters.AddWithValue("$total", total);
            cmd.ExecuteNonQuery();

            return Results.Ok(new { accepted = true, total });
        });


        // ------------------------------------------------------------------
        // >>> VULN A06 : CWE-841 : missing business-logic limit. The coupon has
        //     a redemption counter, and the code faithfully increments it -
        //     but no rule anywhere says what the counter is *for*. Redeem
        //     STAFF50 a thousand times and the discount stacks a thousand times.
        //
        //     There is also a TOCTOU race: read, then write, with no
        //     transaction and no row lock, so concurrent requests all pass.
        // ------------------------------------------------------------------
        g.MapPost("/redeem", (string code) =>
        {
            using var cn = AppDatabase.Open();

            using var read = cn.CreateCommand();
            read.CommandText = "SELECT PercentOff, TimesRedeemed FROM Coupons WHERE Code = $c";
            read.Parameters.AddWithValue("$c", code);
            using var r = read.ExecuteReader();
            if (!r.Read()) return Results.NotFound();
            var percent = r.GetInt32(0);
            var used = r.GetInt32(1);
            r.Close();

            using var write = cn.CreateCommand();
            write.CommandText = "UPDATE Coupons SET TimesRedeemed = $n WHERE Code = $c";
            write.Parameters.AddWithValue("$n", used + 1);
            write.Parameters.AddWithValue("$c", code);
            write.ExecuteNonQuery();

            return Results.Ok(new { code, percentOff = percent, timesRedeemed = used + 1 });
        });


        // ------------------------------------------------------------------
        // >>> VULN A06 : CWE-307 : no rate limiting anywhere on the design.
        //     This endpoint tells a caller whether an email is registered, and
        //     will answer as fast and as often as it is asked. That is a user
        //     enumeration oracle and a credential-stuffing accelerator - and
        //     it was never a *bug*, it was a product decision to give
        //     "helpful" feedback.
        // ------------------------------------------------------------------
        g.MapGet("/account-exists", (string email) =>
        {
            using var cn = AppDatabase.Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM Users WHERE Email = $e";
            cmd.Parameters.AddWithValue("$e", email);
            var exists = Convert.ToInt32(cmd.ExecuteScalar()) > 0;
            return Results.Ok(new { email, exists });
        });


        // ------------------------------------------------------------------
        // >>> VULN A06 : CWE-640 : password recovery through a "security
        //     question" whose answer is public information. Implemented
        //     perfectly. Designed to authenticate a stranger using facts a
        //     stranger can look up.
        // ------------------------------------------------------------------
        g.MapPost("/recover", (RecoveryRequest req) =>
        {
            if (!string.Equals(req.MothersMaidenName, "Kovac", StringComparison.OrdinalIgnoreCase))
                return Results.BadRequest(new { error = "Incorrect answer" });

            using var cn = AppDatabase.Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "SELECT PasswordHash FROM Users WHERE Username = $u";
            cmd.Parameters.AddWithValue("$u", req.Username ?? "");
            var hash = cmd.ExecuteScalar() as string;

            // and it hands back the hash, so it is an offline-cracking oracle too
            return Results.Ok(new { username = req.Username, passwordHash = hash });
        });


        // ------------------------------------------------------------------
        //  N1 FACILITATION NOTE
        //
        //  Run the four defects above past the room and ask, for each:
        //    1. Would a SAST tool flag it?              (No - all four.)
        //    2. Would a DAST scan flag it?              (Partially, at best.)
        //    3. What question, asked during design,
        //       would have prevented it?
        //
        //  The third question is the whole point of the node. Suggested answers:
        //    checkout        - "who is authoritative for this value?"
        //    redeem          - "what is the limit, and what enforces it?"
        //    account-exists  - "what does a wrong answer reveal?"
        //    recover         - "is this secret actually secret?"
        // ------------------------------------------------------------------
    }

    public record CheckoutRequest(string Sku, int Quantity, double UnitPrice);
    public record RecoveryRequest(string Username, string MothersMaidenName);
}
