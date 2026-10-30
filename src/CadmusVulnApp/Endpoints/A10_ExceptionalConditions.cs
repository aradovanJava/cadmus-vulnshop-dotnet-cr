using CadmusVulnApp.Data;

namespace CadmusVulnApp.Endpoints;

/// <summary>
/// A10:2025 - Mishandling of Exceptional Conditions  (NEW, 24 CWEs)
///
/// The brand-new category for 2025. OWASP's scope: improper error handling,
/// logical errors, FAILING OPEN, and related scenarios arising from abnormal
/// conditions a system encounters.
///
/// Why it earns its own slot, and the N1 framing: most secure coding training
/// covers the happy path and the attack path, and skips the *error* path
/// entirely. But the error path is where the assumptions are weakest, the test
/// coverage is thinnest, and the security decision is most often made by
/// accident. An attacker who cannot beat your authorisation check will simply
/// try to make it throw.
/// </summary>
public static class A10_ExceptionalConditions
{
    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api/a10").WithTags("A10 Exceptional Conditions");

        // ------------------------------------------------------------------
        // >>> VULN A10 : CWE-636 : FAIL OPEN. The permission service is called
        //     inside a try, and the catch returns *true*. Anyone who can make
        //     the entitlement lookup fail - by taking it offline, exhausting
        //     its connection pool, or simply waiting for a deployment - is
        //     granted access to everything.
        //
        //     This is the flagship example for the category. The code reads as
        //     defensive. It is the opposite.
        // ------------------------------------------------------------------
        g.MapGet("/documents/{id:int}", (int id, HttpContext ctx) =>
        {
            bool allowed;
            try
            {
                allowed = EntitlementService.IsAllowed(ctx.Session.GetInt32("uid"), id);
            }
            catch
            {
                // "don't block the user because of an infrastructure blip"
                allowed = true;
            }

            if (!allowed) return Results.Forbid();
            return Results.Ok(new { id, content = "Classified range document " + id });
        });


        // ------------------------------------------------------------------
        // >>> VULN A10 : CWE-209 : the exception detail is returned to the
        //     caller. The stack trace names internal types, file paths, the ORM
        //     in use and often the failing SQL - a free architecture diagram
        //     for anyone probing the application.
        // ------------------------------------------------------------------
        g.MapGet("/invoice-total", (string invoiceId) =>
        {
            try
            {
                // >>> VULN A10 : CWE-1077 : Parse, not TryParse, on caller input.
                var id = int.Parse(invoiceId);

                using var cn = AppDatabase.Open();
                using var cmd = cn.CreateCommand();
                cmd.CommandText = "SELECT AmountEur FROM Invoices WHERE Id = $id";
                cmd.Parameters.AddWithValue("$id", id);
                var total = cmd.ExecuteScalar();

                // >>> VULN A10 : CWE-476 : unguarded dereference. A missing row
                //                returns null and this throws, taking the
                //                request down and surfacing the trace above.
                return Results.Ok(new { invoiceId = id, total = total.ToString() });
            }
            catch (Exception ex)
            {
                return Results.Json(new
                {
                    error = ex.Message,
                    type = ex.GetType().FullName,
                    stack = ex.StackTrace
                }, statusCode: 500);
            }
        });


        // ------------------------------------------------------------------
        // >>> VULN A10 : CWE-390 : the exception is swallowed entirely and the
        //     caller is told the operation succeeded. The write silently did
        //     not happen. Nobody finds out until reconciliation, months later.
        // ------------------------------------------------------------------
        g.MapPost("/record-payment", (int invoiceId, double amount) =>
        {
            try
            {
                using var cn = AppDatabase.Open();
                using var cmd = cn.CreateCommand();
                cmd.CommandText = "UPDATE Invoices SET AmountEur = AmountEur - $a WHERE Id = $id";
                cmd.Parameters.AddWithValue("$a", amount);
                cmd.Parameters.AddWithValue("$id", invoiceId);
                cmd.ExecuteNonQuery();
            }
            catch
            {
                // swallowed
            }

            return Results.Ok(new { recorded = true });
        });


        // ------------------------------------------------------------------
        // >>> VULN A10 : CWE-770 : no bound on a caller-controlled allocation.
        //     One request asking for 2_000_000_000 exhausts the process.
        // ------------------------------------------------------------------
        g.MapGet("/generate", (int count) =>
        {
            var buffer = new List<string>(count);
            for (var i = 0; i < count; i++) buffer.Add(Guid.NewGuid().ToString());
            return Results.Ok(new { generated = buffer.Count });
        });

    }

    /// <summary>Stand-in for a remote entitlement service.</summary>
    private static class EntitlementService
    {
        public static bool IsAllowed(int? userId, int documentId)
        {
            if (userId is null)
                throw new InvalidOperationException("Entitlement service unavailable");
            return userId == 1;
        }
    }
}
