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
    // >>> VULN A04 : CWE-798 : hard-coded symmetric key committed to source
    //                control. Rotating it now requires a code change, a build
    //                and a deploy - which is why it will never be rotated.
    private static readonly byte[] Key =
        Encoding.UTF8.GetBytes("CadmusRange2026SecretKey_32Bytes");

    // >>> VULN A04 : CWE-329 : a fixed, non-random IV. Under CBC this makes
    //                the ciphertext deterministic: identical plaintexts encrypt
    //                to identical bytes, so an observer learns equality without
    //                learning the key.
    private static readonly byte[] StaticIv = new byte[16];

    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api/a04").WithTags("A04 Cryptographic Failures");

        // ------------------------------------------------------------------
        // >>> VULN A04 : CWE-327 : broken primitive plus broken mode. ECB
        //     encrypts each 16-byte block independently, so structure in the
        //     plaintext survives into the ciphertext, and there is no
        //     authentication tag at all - ciphertext can be tampered with
        //     undetected.
        // ------------------------------------------------------------------
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


        // ------------------------------------------------------------------
        // >>> VULN A04 : CWE-338 : System.Random is a linear congruential
        //     generator seeded from the clock. Given two or three tokens an
        //     attacker recovers the seed and predicts every token that will
        //     ever be issued. This same generator backs the A07 password-reset
        //     token, which is where it becomes a full account takeover.
        // ------------------------------------------------------------------
        g.MapGet("/session-token", () =>
        {
            var rng = new Random();
            var token = string.Concat(Enumerable.Range(0, 24)
                .Select(_ => "abcdefghijklmnopqrstuvwxyz0123456789"[rng.Next(36)]));
            return Results.Ok(new { token });
        });


        // ------------------------------------------------------------------
        // >>> VULN A04 : CWE-759 / CWE-916 : unsalted MD5 verification, and a
        //     non-constant-time string comparison that leaks the position of
        //     the first differing character through response timing.
        // ------------------------------------------------------------------
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


        // ------------------------------------------------------------------
        // >>> VULN A04 : CWE-295 : certificate validation disabled outright.
        //     Every outbound TLS connection this handler makes is trivially
        //     interceptable; the padlock is decorative.
        // ------------------------------------------------------------------
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
