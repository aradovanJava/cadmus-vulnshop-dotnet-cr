// =============================================================================
//  CADMUS-CR-13  |  Secure Coding .NET/C#
//  Deliberately Vulnerable Reference Application
//  Target: .NET 10 (LTS)  |  OWASP Top 10:2025
// =============================================================================
//
//  ####################  TRAINING ARTEFACT - DO NOT DEPLOY  ####################
//
//  This application contains intentional security defects. It exists only to be
//  scanned, discussed and repaired inside the CADMUS Cyber Range sandbox.
//  Run it on an isolated host, bound to loopback, never on a routable network.
//
//  Every defect is marked with a machine-greppable tag:
//
//      // >>> VULN A0X : <CWE-nnn> : <short name>
//  Find them all:   grep -rn ">>> VULN" src/
//
// =============================================================================

using CadmusVulnApp.Data;
using CadmusVulnApp.Endpoints;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHttpClient();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    // >>> VULN A02 : CWE-1004 : session cookie is not HttpOnly and not Secure,
    //                so it is readable by any script that lands on the page.
    options.Cookie.HttpOnly = false;
    options.Cookie.SecurePolicy = CookieSecurePolicy.None;
    options.Cookie.SameSite = SameSiteMode.None;
    options.IdleTimeout = TimeSpan.FromHours(12);

});

// >>> VULN A01 : CWE-942 : wildcard CORS combined with credentials.
//                Any origin on the internet can issue authenticated
//                cross-site requests and read the responses.
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy
        .SetIsOriginAllowed(_ => true)
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials());

});

// >>> VULN A09 : CWE-778 : logging is turned down to Error, so every
//                authentication failure, authorisation denial and input
//                validation rejection disappears before it is written.
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Error);


var app = builder.Build();

AppDatabase.Initialise(app.Configuration);

// >>> VULN A02 : CWE-489 : the developer exception page is enabled
//                unconditionally, including in Production. Full stack traces,
//                source snippets, routing tables and configuration values are
//                served to anonymous callers on any unhandled exception.
app.UseDeveloperExceptionPage();


// >>> VULN A02 : CWE-548 : static file serving with directory browsing enabled.
//                wwwroot/backup/ is listable, and it contains a database dump.
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseDirectoryBrowser();

// >>> VULN A02 : CWE-693 : no security response headers are emitted.
//                No Content-Security-Policy, no X-Content-Type-Options,
//                no Strict-Transport-Security, no Referrer-Policy.
//                The A05 reflected-XSS endpoint is exploitable partly because
//                there is no CSP to contain it.
//

// >>> VULN A02 : CWE-319 : HTTPS redirection is commented out, so bearer
//                tokens and session cookies travel in cleartext.
// app.UseHttpsRedirection();

app.UseCors();
app.UseSession();

// >>> VULN A02 : CWE-1188 : Swagger UI, including every internal admin
//                endpoint, is exposed in all environments without auth.
app.UseSwagger();
app.UseSwaggerUI();

// ---------------------------------------------------------------------------
//  OWASP Top 10:2025 - one module per category
// ---------------------------------------------------------------------------
A01_BrokenAccessControl.Map(app);
A02_SecurityMisconfiguration.Map(app);
A03_SoftwareSupplyChain.Map(app);
A04_CryptographicFailures.Map(app);
A05_Injection.Map(app);
A06_InsecureDesign.Map(app);
A07_AuthenticationFailures.Map(app);
A08_IntegrityFailures.Map(app);
A09_LoggingAndAlerting.Map(app);
A10_ExceptionalConditions.Map(app);

app.MapGet("/health", () => Results.Ok(new { status = "up", build = "cadmus-cr-13" }));

Console.WriteLine("""
    ---------------------------------------------------------------
     CADMUS-CR-13 vulnerable reference application
     TRAINING USE ONLY - contains intentional security defects
     Swagger UI: http://localhost:5080/swagger
    ---------------------------------------------------------------
    """);

app.Run();
