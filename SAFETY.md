# SAFETY — read before you start the application

`cadmus-vulnshop-dotnet-cr` is **deliberately vulnerable**. It contains
authorisation bypasses, injection points including **OS command injection**
(a remote-code-execution path), unsafe deserialisation, plugin loading from a
caller-supplied path, and a configuration written to be as unsafe as a
plausible real one.

## Rules

1. **Sandbox only.** Run it inside the Cyber Range VM (SC1), or on a machine
   you are prepared to treat as compromised.
2. **Loopback only.** `tools\run-app.ps1` binds it to `127.0.0.1:5080`, and
   `docker-compose.yml` binds every port to `127.0.0.1`. Do not change either.
   Never expose it to a routable network.
3. **No real data, no real credentials.** The database is SQLite, created and
   seeded with fabricated records on first start. The seeded accounts and every
   secret in `appsettings.json` are public by design — never reuse any of them.
4. **Do not copy code from this repository into anything real.** Several
   patterns here look like reasonable engineering and are not.
5. **Work individually** and do not compare findings until the debrief.

## What "vulnerable" means here

The defects are the kind that appear in code review and in scanner output. The
requests the lab guide asks you to send are ordinary HTTP requests whose only
purpose is to show that a finding is reachable rather than theoretical.

If you find a weakness the instructor did not mention, report it — the
inventory is a teaching aid, not a claim of completeness.
