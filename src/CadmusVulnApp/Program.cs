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
    options.Cookie.HttpOnly = false;
    options.Cookie.SecurePolicy = CookieSecurePolicy.None;
    options.Cookie.SameSite = SameSiteMode.None;
    options.IdleTimeout = TimeSpan.FromHours(12);

});

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy
        .SetIsOriginAllowed(_ => true)
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials());

});

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Error);


var app = builder.Build();

AppDatabase.Initialise(app.Configuration);

app.UseDeveloperExceptionPage();


app.UseDefaultFiles();
app.UseStaticFiles();
app.UseDirectoryBrowser();



app.UseCors();
app.UseSession();

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
