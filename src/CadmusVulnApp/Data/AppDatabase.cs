using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;

namespace CadmusVulnApp.Data;

/// <summary>
/// Creates and seeds the training database. Raw ADO.NET is used deliberately:
/// it keeps the SQL visible so the A05 injection defects are legible to
/// trainees and detectable by SonarQube's C# taint analysis rules.
/// </summary>
public static class AppDatabase
{
    public static string ConnectionString { get; private set; } =
        "Data Source=cadmus-range.db";

    public static void Initialise(IConfiguration config)
    {
        ConnectionString = config.GetConnectionString("Default")
                           ?? "Data Source=cadmus-range.db";

        using var cn = Open();

        Execute(cn, """
            CREATE TABLE IF NOT EXISTS Users (
                Id            INTEGER PRIMARY KEY AUTOINCREMENT,
                Username      TEXT NOT NULL,
                PasswordHash  TEXT NOT NULL,
                Role          TEXT NOT NULL,
                Email         TEXT,
                Iban          TEXT,
                FailedLogins  INTEGER NOT NULL DEFAULT 0,
                ResetToken    TEXT
            );
            """);

        Execute(cn, """
            CREATE TABLE IF NOT EXISTS Invoices (
                Id       INTEGER PRIMARY KEY AUTOINCREMENT,
                OwnerId  INTEGER NOT NULL,
                Customer TEXT NOT NULL,
                AmountEur REAL NOT NULL,
                Notes    TEXT
            );
            """);

        Execute(cn, """
            CREATE TABLE IF NOT EXISTS Orders (
                Id        INTEGER PRIMARY KEY AUTOINCREMENT,
                UserId    INTEGER NOT NULL,
                Sku       TEXT NOT NULL,
                Quantity  INTEGER NOT NULL,
                UnitPrice REAL NOT NULL,
                Total     REAL NOT NULL
            );
            """);

        Execute(cn, """
            CREATE TABLE IF NOT EXISTS Coupons (
                Code            TEXT PRIMARY KEY,
                PercentOff      INTEGER NOT NULL,
                TimesRedeemed   INTEGER NOT NULL DEFAULT 0
            );
            """);

        using var check = cn.CreateCommand();
        check.CommandText = "SELECT COUNT(*) FROM Users";
        if (Convert.ToInt32(check.ExecuteScalar()) > 0) return;

        Seed(cn, "admin",  "admin123",   "Administrator", "admin@cadmus.local",  "HR1723600000000000000");
        Seed(cn, "aradovan", "Password1", "Auditor",       "a.radovan@cadmus.local", "HR1723600000011111111");
        Seed(cn, "trainee", "trainee",    "User",          "trainee@cadmus.local", "HR1723600000022222222");

        Execute(cn, """
            INSERT INTO Invoices (OwnerId, Customer, AmountEur, Notes) VALUES
              (1, 'Ministry of Health',   48200.00, 'Q3 framework - CONFIDENTIAL'),
              (2, 'Regional Hospital NW', 12750.50, 'Penetration test retainer'),
              (3, 'Cadmus Trainee Ltd',     990.00, 'Course materials');
            """);

        Execute(cn, """
            INSERT INTO Coupons (Code, PercentOff, TimesRedeemed) VALUES
              ('WELCOME10', 10, 0),
              ('STAFF50',   50, 0);
            """);
    }

    private static void Seed(SqliteConnection cn, string user, string password,
                             string role, string email, string iban)
    {
        using var cmd = cn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO Users (Username, PasswordHash, Role, Email, Iban)
            VALUES ($u, $p, $r, $e, $i)
            """;
        cmd.Parameters.AddWithValue("$u", user);
        cmd.Parameters.AddWithValue("$p", LegacyHash(password));
        cmd.Parameters.AddWithValue("$r", role);
        cmd.Parameters.AddWithValue("$e", email);
        cmd.Parameters.AddWithValue("$i", iban);
        cmd.ExecuteNonQuery();
    }

    public static string LegacyHash(string input)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static SqliteConnection Open()
    {
        var cn = new SqliteConnection(ConnectionString);
        cn.Open();
        return cn;
    }

    private static void Execute(SqliteConnection cn, string sql)
    {
        using var cmd = cn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }
}
