using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Services;
using System.Net;

var builder = WebApplication.CreateBuilder(args);

// Configure Kestrel to require client certificates (mutual TLS)
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
    });
});

// Configure certificate authentication middleware
builder.Services.AddAuthentication(
        CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = ctx =>
            {
                var cert = ctx.ClientCertificate;
                // Basic validation: check cert not null and has a subject
                if (cert == null)
                {
                    ctx.Fail("No client certificate.");
                    return Task.CompletedTask;
                }

                // Example acceptance rule: check expiration
                if (DateTime.UtcNow < cert.NotBefore || DateTime.UtcNow > cert.NotAfter)
                {
                    ctx.Fail("Client certificate expired or not yet valid.");
                    return Task.CompletedTask;
                }

                // Map certificate to a ClaimsPrincipal. Customize mapping logic as required.
                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, cert.Thumbprint),
                    new Claim(ClaimTypes.Name, cert.Subject),
                    new Claim("x5t", cert.GetCertHashString())
                };

                var identity = new ClaimsIdentity(claims, ctx.Scheme.Name);
                ctx.Principal = new ClaimsPrincipal(identity);
                ctx.Success();

                return Task.CompletedTask;
            },
            OnAuthenticationFailed = ctx =>
            {
                ctx.Fail("Certificate authentication failed.");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

// Register the SAML builder service (loads signing cert from config)
builder.Services.AddSingleton<Saml1AssertionBuilder>(sp =>
{
    var cfg = builder.Configuration;
    var pfxPath = cfg["SigningCert:Path"] ?? "sts-signing.pfx";
    var pfxPassword = cfg["SigningCert:Password"] ?? "";
    var signingCert = new X509Certificate2(pfxPath, pfxPassword, X509KeyStorageFlags.MachineKeySet);
    return new Saml1AssertionBuilder(signingCert);
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Simple WS-Fed passive endpoint
app.MapGet("/wsfed", async (HttpContext http, Saml1AssertionBuilder samlBuilder) =>
{
    // Validate WS-Fed sign-in action
    // Example query parameters:
    // wa=wsignin1.0
    // wreply=<relying party wreply>
    // wctx=<opaque context>
    var req = http.Request;
    var query = req.Query;
    var wa = query["wa"].ToString();
    var wreply = query["wreply"].ToString();
    var wctx = query["wctx"].ToString();

    if (!string.Equals(wa, "wsignin1.0", StringComparison.OrdinalIgnoreCase))
    {
        http.Response.StatusCode = (int)HttpStatusCode.BadRequest;
        await http.Response.WriteAsync("Unsupported action");
        return;
    }

    if (string.IsNullOrEmpty(wreply))
    {
        http.Response.StatusCode = (int)HttpStatusCode.BadRequest;
        await http.Response.WriteAsync("Missing wreply");
        return;
    }

    // Ensure mutual TLS certificate authentication supplied a user
    if (!http.User?.Identity?.IsAuthenticated ?? true)
    {
        http.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        await http.Response.WriteAsync("Client certificate is required");
        return;
    }

    // Extract principal information to include in SAML assertion
    var subjectName = http.User.Identity!.Name ?? http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "unknown";

    // Build SAML 1.1 assertion (signed XML)
    var assertionXml = samlBuilder.BuildSignedAssertion(
        subjectName,
        audienceUri: wreply,
        attributes: new Dictionary<string, string>
        {
            { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "user@example.com" },
            { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", subjectName }
        },
        notBefore: DateTime.UtcNow.AddMinutes(-5),
        notOnOrAfter: DateTime.UtcNow.AddMinutes(30)
    );

    // Wrap the assertion in a WS-Trust RequestSecurityTokenResponse (simple form)
    var rstr = $@"<wst:RequestSecurityTokenResponse xmlns:wst=""http://schemas.xmlsoap.org/ws/2005/02/trust"">
  <wst:RequestedSecurityToken>
    {assertionXml}
  </wst:RequestedSecurityToken>
</wst:RequestSecurityTokenResponse>";

    // HTML-encode the rstr for safe inclusion in the form value
    var encodedRstr = System.Net.WebUtility.HtmlEncode(rstr);

    // Return an auto-posting HTML form (WS-Fed passive)
    var html = $@"<!doctype html>
<html>
  <body>
    <form id=""f"" method=""post"" action=""{WebUtility.HtmlEncode(wreply)}"">
      <input type=""hidden"" name=""wa"" value=""wsignin1.0"" />
      <input type=""hidden"" name=""wresult"" value=""{encodedRstr}"" />
      <input type=""hidden"" name=""wctx"" value=""{WebUtility.HtmlEncode(wctx)}"" />
      <noscript>
        <p>JavaScript is required to complete the sign-in. Press the button below to continue.</p>
        <button type=""submit"">Continue</button>
      </noscript>
    </form>
    <script>document.getElementById('f').submit();</script>
  </body>
</html>";

    http.Response.ContentType = "text/html; charset=utf-8";
    await http.Response.WriteAsync(html);
});

app.Run();