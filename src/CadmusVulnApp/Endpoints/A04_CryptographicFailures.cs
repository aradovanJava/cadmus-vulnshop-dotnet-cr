using System.Security.Cryptography;
using System.Text;
using CadmusVulnApp.Data;

namespace CadmusVulnApp.Endpoints;

/// <summary>
/// A04:2025 - Cryptographic Failures  (down from #2, 32 CWEs, 3.80% incidence)
///
/// Note the number: A04 has the *highest* incidence in the whole 2025 dataset
/// at 3.80%, yet ranks fourth, because ranking weights exploitability and
/// impact as well as prevalence. Useful slide material - it shows why the list
/// is a risk ranking, not a frequency table.
///
/// Every defect here is a design-time decision that no amount of careful
/// implementation later can rescue.
/// </summary>
public static class A04_CryptographicFailures
{
    private static readonly byte[] Key =
        Encoding.UTF8.GetBytes("CadmusRange2026SecretKey_32Bytes");

    private static readonly byte[] StaticIv = new byte[16];

    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api/a04").WithTags("A04 Cryptographic Failures");

        g.MapPost("/protect", (PlainText body) =>
        {
            using var aes = Aes.Create();
            aes.Key = Key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;

            using var enc = aes.CreateEncryptor();
            var input = Encoding.UTF8.GetBytes(body.Value ?? "");
            var cipher = enc.TransformFinalBlock(input, 0, input.Length);

            return Results.Ok(new { protectedValue = Convert.ToBase64String(cipher) });
        });


        g.MapGet("/session-token", () =>
        {
            var rng = new Random();
            var token = string.Concat(Enumerable.Range(0, 24)
                .Select(_ => "abcdefghijklmnopqrstuvwxyz0123456789"[rng.Next(36)]));
            return Results.Ok(new { token });
        });


        g.MapPost("/verify-password", (Credentials c) =>
        {
            using var cn = AppDatabase.Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "SELECT PasswordHash FROM Users WHERE Username = $u";
            cmd.Parameters.AddWithValue("$u", c.Username ?? "");
            var stored = cmd.ExecuteScalar() as string;
            if (stored is null) return Results.NotFound();

            var supplied = AppDatabase.LegacyHash(c.Password ?? "");
            return Results.Ok(new { valid = stored == supplied });
        });


        g.MapGet("/partner-balance", async () =>
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            using var http = new HttpClient(handler);
            var body = await http.GetStringAsync("https://partner.cadmus-range.local/balance");
            return Results.Text(body);
        });

    }

    public record PlainText(string Value);
    public record Credentials(string Username, string Password);
}
