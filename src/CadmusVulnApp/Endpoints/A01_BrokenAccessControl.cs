using CadmusVulnApp.Data;
using Microsoft.Data.Sqlite;

namespace CadmusVulnApp.Endpoints;

/// <summary>
/// A01:2025 - Broken Access Control  (#1, 40 CWEs, 3.73% incidence)
///
/// New in 2025: Server-Side Request Forgery is no longer its own category.
/// It has been rolled into A01, on the reasoning that SSRF is the server
/// reaching a resource the caller was never authorised to reach.
///
/// Root cause taught in N1: authorisation is a *design* property. It has to be
/// decided once, at the trust boundary, and enforced by default. Every defect
/// below is the same mistake - the decision was left to the individual handler.
/// </summary>
public static class A01_BrokenAccessControl
{
    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api/a01").WithTags("A01 Broken Access Control");

        g.MapGet("/invoices/{id:int}", (int id, HttpContext ctx) =>
        {
            using var cn = AppDatabase.Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "SELECT Id, OwnerId, Customer, AmountEur, Notes FROM Invoices WHERE Id = $id";
            cmd.Parameters.AddWithValue("$id", id);

            using var r = cmd.ExecuteReader();
            if (!r.Read()) return Results.NotFound();

            return Results.Ok(new
            {
                Id = r.GetInt32(0),
                OwnerId = r.GetInt32(1),
                Customer = r.GetString(2),
                AmountEur = r.GetDouble(3),
                Notes = r.IsDBNull(4) ? null : r.GetString(4)
            });
        });


        g.MapGet("/admin/users", (HttpContext ctx) =>
        {
            var role = ctx.Request.Headers["X-Role"].ToString();
            if (role != "Administrator")
                return Results.Forbid();

            var users = new List<object>();
            using var cn = AppDatabase.Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "SELECT Id, Username, Role, Email, Iban, PasswordHash FROM Users";
            using var r = cmd.ExecuteReader();
            while (r.Read())
                users.Add(new
                {
                    Id = r.GetInt32(0),
                    Username = r.GetString(1),
                    Role = r.GetString(2),
                    Email = r.GetString(3),
                    Iban = r.GetString(4),
                    PasswordHash = r.GetString(5)   // also A04: hashes leak to the client
                });
            return Results.Ok(users);
        });


        g.MapGet("/promote", (string username, HttpContext ctx) =>
        {
            using var cn = AppDatabase.Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "UPDATE Users SET Role = 'Administrator' WHERE Username = $u";
            cmd.Parameters.AddWithValue("$u", username);
            cmd.ExecuteNonQuery();
            return Results.Ok($"{username} promoted");
        });


        g.MapGet("/avatar-proxy", async (string url, IHttpClientFactory factory) =>
        {
            var http = factory.CreateClient();
            var body = await http.GetStringAsync(url);
            return Results.Text(body);
        });

    }
}
