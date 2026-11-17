using FSCA.CertProcessing;
using FSCA.Support;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Services;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Serilog;
using System.Text;
using Microsoft.AspNetCore.Authentication;

// ===== CONFIGURE SERILOG FIRST (before anything ELSE) =====
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(new ConfigurationBuilder()
        .SetBasePath(Directory.GetCurrentDirectory())
        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true)
        .Build())
    .CreateLogger();

try
{
    Log.Information("========================================");
    Log.Information("Starting Mini-STS Application");
    Log.Information("========================================");

    var builder = WebApplication.CreateBuilder(args);

    // Replace default logging with Serilog
    builder.Host.UseSerilog();

    builder.Services.AddTransient<DoDNIPRCertProcessor>();
    builder.Services.AddTransient<DoDSIPRCertProcessor>();
    builder.Services.AddTransient<DefaultCertProcessor>();

    var tokenLifetimeHours = builder.Configuration.GetValue<double>("TokenLifetimeHours", 0.5);
    if (tokenLifetimeHours <= 0) tokenLifetimeHours = 0.5;

    Log.Information("Configuration loaded. TokenLifetimeHours={TokenLifetime}", tokenLifetimeHours);

    // Load certificate validation options from configuration
    var validationOptions = new ValidationOptions();
    builder.Configuration.GetSection("CertificateValidation").Bind(validationOptions);
    Log.Information("Certificate validation configured: ValidateChain={ValidateChain}, RequireClientAuthEku={RequireClientAuthEku}, RequireSmartCardLogonEku={RequireSmartCardLogonEku}",
        validationOptions.ValidateChain, validationOptions.RequireClientAuthEku, validationOptions.RequireSmartCardLogonEku);

    builder.Services.AddSingleton(validationOptions);

    builder.WebHost.ConfigureKestrel(options =>
    {
        options.ConfigureHttpsDefaults(httpsOptions =>
        {
            // Allow both with and without certificate
            httpsOptions.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        });
    });

    // Add Certificate Forwarding services if running behind IIS
    builder.Services.AddCertificateForwarding(options =>
    {
        options.CertificateHeader = "X-ARR-ClientCert";
    });

    builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
        .AddCertificate(options =>
        {
            options.AllowedCertificateTypes = CertificateTypes.All;
            options.Events = new CertificateAuthenticationEvents
            {
                OnCertificateValidated = ctx =>
                {
                    var cert = ctx.ClientCertificate;
                    if (cert == null)
                    {
                        Log.Warning("Certificate validation failed: No client certificate");
                        ctx.Fail("No client certificate.");
                        return Task.CompletedTask;
                    }

                    // Get validation options from DI
                    var validationOpts = ctx.HttpContext.RequestServices.GetRequiredService<ValidationOptions>();
                    var validationLogger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();

                    // Perform comprehensive validation
                    var validationResult = CertValidators.ValidateCertificate(cert, validationOpts, validationLogger);

                    if (!validationResult.IsValid)
                    {
                        var errors = string.Join("; ", validationResult.Errors);
                        Log.Warning("Certificate validation failed: {Errors}. Subject={Subject}", errors, cert.Subject);
                        ctx.Fail($"Certificate validation failed: {errors}");
                        return Task.CompletedTask;
                    }

                    Log.Information("Certificate validation successful: {Subject}", cert.Subject);

                    var claims = new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, cert.Thumbprint),
                        new Claim(ClaimTypes.Name, cert.Subject),
                        new Claim("x5t", cert.GetCertHashString())
                    };

                    ctx.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, ctx.Scheme.Name));
                    ctx.Success();
                    Log.Debug("Certificate validated successfully: {Subject}", cert.Subject);
                    return Task.CompletedTask;
                },
                OnAuthenticationFailed = ctx =>
                {
                    Log.Error("Certificate authentication failed: {FailureMessage}", ctx.Exception?.Message);
                    ctx.Fail("Certificate authentication failed.");
                    return Task.CompletedTask;
                }
            };
        });

    builder.Services.AddAuthorization(options =>
    {
        // Default policy: no authentication required
        // Endpoints must explicitly opt-in with .RequireAuthorization()
        options.FallbackPolicy = null;
        options.DefaultPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
            .RequireAssertion(_ => true)  // Always allow
            .Build();
    });

    // Register SecurityTokenService
    builder.Services.AddSingleton<SecurityTokenService>(sp =>
    {
        var cfg = builder.Configuration;
        var thumbprint = cfg["SignThumbprint"]?.Replace(" ", string.Empty);

        if (string.IsNullOrWhiteSpace(thumbprint))
        {
            Log.Fatal("Configuration error: SignThumbprint is missing or empty");
            throw new InvalidOperationException("Configuration key 'SignThumbprint' is missing or empty.");
        }

        Log.Information("Loading signing certificate with thumbprint: {Thumbprint}", thumbprint);

        X509Certificate2? found = null;
        using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
        {
            store.Open(OpenFlags.ReadOnly);
            var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
            if (matches.Count > 0)
            {
                found = new X509Certificate2(matches[0]);
                Log.Information("Signing certificate found: Subject={Subject}, Issuer={Issuer}", 
                    found.Subject, found.Issuer);
            }
        }

        if (found == null || !found.HasPrivateKey)
        {
            Log.Fatal("Signing certificate with thumbprint '{Thumbprint}' not found or has no private key", thumbprint);
            throw new InvalidOperationException($"Signing certificate with thumbprint '{thumbprint}' not found or has no private key.");
        }

        var issuer = cfg["Issuer"] ?? "Mini-STS";
        Log.Information("SecurityTokenService configured with Issuer={Issuer}", issuer);
        
        var logger = sp.GetRequiredService<ILogger<SecurityTokenService>>();
        return new SecurityTokenService(found, issuer, TimeSpan.FromHours(tokenLifetimeHours), logger);
    });

    // Load allowed relying parties
    var allowedHosts = builder.Configuration
        .GetSection("RelyingParties")
        .Get<string[]>()?
        .Select(e => e?.Trim().ToLowerInvariant())
        .Where(s => !string.IsNullOrEmpty(s))
        .Distinct()
        .ToArray() ?? Array.Empty<string>();

    builder.Services.AddSingleton<IReadOnlyCollection<string>>(allowedHosts!);
    
    Log.Information("Allowed relying parties: {RelyingParties}", string.Join(", ", allowedHosts ?? Array.Empty<string>()));

    static bool TryGetHostPortFromUri(string uriString, out string hostPort)
    {
        hostPort = string.Empty;
        if (!Uri.TryCreate(uriString, UriKind.Absolute, out var u)) return false;
        
        hostPort = (u.IsDefaultPort || (u.Scheme == "http" && u.Port == 80) || (u.Scheme == "https" && u.Port == 443))
            ? u.Host.ToLowerInvariant()
            : $"{u.Host.ToLowerInvariant()}:{u.Port}";
        
        return true;
    }

    var app = builder.Build();

    // Diagnostic middleware at the TOP of the pipeline so we can see in the Serilog
    // file whether a given request actually reached the managed pipeline. If the
    // browser shows a 404 but no [INCOMING] line is logged for that path, the 404
    // is being produced by IIS (custom errors, sub-application path, URL Rewrite,
    // stale web.config on the server) and not by ASP.NET Core.
    app.Use(async (ctx, next) =>
    {
        Log.Information(
            "[INCOMING] {Method} {Scheme}://{Host}{PathBase}{Path}{Query} from {RemoteIp} HasClientCert={HasCert}",
            ctx.Request.Method,
            ctx.Request.Scheme,
            ctx.Request.Host.Value,
            ctx.Request.PathBase.Value,
            ctx.Request.Path.Value,
            ctx.Request.QueryString.Value,
            ctx.Connection.RemoteIpAddress,
            ctx.Connection.ClientCertificate != null);
        await next();
        Log.Information(
            "[OUTGOING] {Method} {Path} -> {StatusCode}",
            ctx.Request.Method,
            ctx.Request.Path.Value,
            ctx.Response.StatusCode);
    });

    // Add certificate forwarding middleware if using IIS
    app.UseCertificateForwarding();

    // Add Serilog request logging
    app.UseSerilogRequestLogging(options =>
    {
        options.MessageTemplate = "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";
        options.GetLevel = (httpContext, elapsed, ex) => ex != null 
            ? Serilog.Events.LogEventLevel.Error 
            : elapsed > 5000 
                ? Serilog.Events.LogEventLevel.Warning 
                : Serilog.Events.LogEventLevel.Debug;
    });

    app.UseAuthentication();
    app.UseAuthorization();

    // Root endpoint - anonymous
    app.MapGet("/", async (HttpContext http) =>
    {
        http.Response.ContentType = "text/html; charset=utf-8";
        await http.Response.WriteAsync(@"<!doctype html>
<html>
  <head><meta charset=""utf-8""><title>Mini-STS</title></head>
  <body>
    <h1>Mini-STS</h1>
    <p>This application is an authentication service.</p>
    <p>Federation metadata: <a href=""/FederationMetadata/2007-06/FederationMetadata.xml"">/FederationMetadata/2007-06/FederationMetadata.xml</a></p>
  </body>
</html>");
    })
    .AllowAnonymous();

    // Metadata endpoint - anonymous (no cert auth)
    app.MapGet("/FederationMetadata/2007-06/FederationMetadata.xml", (
        HttpContext http,
        IConfiguration configuration) =>
    {
        try
        {
            Log.Information("Generating Federation Metadata XML for {RemoteIp}", http.Connection.RemoteIpAddress);

            var entityId = configuration["FederationMetadata:EntityId"] 
                ?? configuration["Issuer"] 
                ?? "https://localhost";
            var passiveEndpoint = configuration["FederationMetadata:PassiveRequestorEndpoint"] 
                ?? "https://localhost/wsfed";
            var orgName = configuration["FederationMetadata:OrganizationName"] ?? "Mini-STS";
            var orgDisplayName = configuration["FederationMetadata:OrganizationDisplayName"] ?? orgName;
            var orgUrl = configuration["FederationMetadata:OrganizationUrl"] ?? entityId;

            var supportedClaims = configuration.GetSection("FederationMetadata:SupportedClaimTypes")
                .Get<string[]>() ?? Array.Empty<string>();

            // Get signing certificate
            var thumbprint = configuration["SignThumbprint"]?.Replace(" ", string.Empty);
            X509Certificate2? signingCert = null;

            if (!string.IsNullOrWhiteSpace(thumbprint))
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly);
                    var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
                    if (matches.Count > 0)
                    {
                        signingCert = matches[0];
                    }
                }
            }

            var metadata = GenerateFederationMetadata(
                entityId,
                passiveEndpoint,
                orgName,
                orgDisplayName,
                orgUrl,
                supportedClaims,
                signingCert);

            http.Response.ContentType = "application/samlmetadata+xml";
            return Results.Content(metadata, "application/samlmetadata+xml");
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to generate federation metadata");
            return Results.Problem("Failed to generate federation metadata", statusCode: 500);
        }
    })
    .AllowAnonymous();

    // WS-Fed endpoint - requires cert authentication
    app.MapGet("/wsfed", async (HttpContext http, SecurityTokenService sts, ILogger<Program> logger, 
        IReadOnlyCollection<string> allowedRelyingParties, IConfiguration configuration, ValidationOptions validationOptions) =>
    {
        var correlationId = Guid.NewGuid().ToString("N");
        
        try
        {
            logger.LogInformation("========== NEW WS-FEDERATION REQUEST ========== [CorrelationId: {CorrelationId}]", correlationId);
            logger.LogInformation("Request from {RemoteIp}", http.Connection.RemoteIpAddress);
            logger.LogInformation("QueryString: {QueryString}", http.Request.QueryString.Value);

            // Parse WS-Federation request
            WsFederationMessage requestMessage;
            try
            {
                requestMessage = WsFederationMessage.FromQueryString(http.Request.QueryString.Value ?? string.Empty);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to parse WS-Federation message [CorrelationId: {CorrelationId}]", correlationId);
                http.Response.ContentType = "text/html; charset=utf-8";
                await http.Response.WriteAsync(
                    FederatedPassiveSecurityTokenServiceOperations.WriteErrorPage(
                        "Invalid Request",
                        "The authentication request could not be processed because it is not in the correct format.",
                        "The WS-Federation message parameters could not be parsed.",
                        correlationId));
                return;
            }

            logger.LogDebug("Parsed WS-Fed message: wa={Wa}, wtrealm={Wtrealm}, wreply={Wreply}, wctx={Wctx}",
                requestMessage.Wa, requestMessage.Wtrealm, requestMessage.Wreply ?? "(none)", requestMessage.Wctx ?? "(none)");

            if (!string.Equals(requestMessage.Wa, WsFederationConstants.WsFederationActions.SignIn, StringComparison.OrdinalIgnoreCase))
            {
                logger.LogWarning("Unsupported action: {Action}", requestMessage.Wa);
                http.Response.ContentType = "text/html; charset=utf-8";
                await http.Response.WriteAsync(
                    FederatedPassiveSecurityTokenServiceOperations.WriteErrorPage(
                        "Unsupported Action",
                        "The requested authentication action is not supported.",
                        $"Action '{requestMessage.Wa}' is not supported. Only 'wsignin1.0' is allowed.",
                        correlationId));
                return;
            }

            var wtrealm = requestMessage.Wtrealm;
            if (string.IsNullOrEmpty(wtrealm))
            {
                logger.LogWarning("Missing wtrealm parameter");
                http.Response.ContentType = "text/html; charset=utf-8";
                await http.Response.WriteAsync(
                    FederatedPassiveSecurityTokenServiceOperations.WriteErrorPage(
                        "Missing Parameter",
                        "The authentication request is missing required parameters.",
                        "The 'wtrealm' parameter is required but was not provided.",
                        correlationId));
                return;
            }

            if (!TryGetHostPortFromUri(wtrealm, out var realmHostPort))
            {
                logger.LogWarning("Invalid wtrealm URI: {WRealm}", wtrealm);
                http.Response.ContentType = "text/html; charset=utf-8";
                await http.Response.WriteAsync(
                    FederatedPassiveSecurityTokenServiceOperations.WriteErrorPage(
                        "Invalid Request",
                        "The authentication request contains an invalid realm parameter.",
                        $"The wtrealm value '{wtrealm}' is not a valid URI.",
                        correlationId));
                return;
            }

            if (!allowedRelyingParties.Contains(realmHostPort, StringComparer.OrdinalIgnoreCase))
            {
                logger.LogWarning("BLOCKED - Unknown relying party: {WRealmHost} (from wtrealm={WRealm}) [CorrelationId: {CorrelationId}]", 
                    realmHostPort, wtrealm, correlationId);
                http.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                http.Response.ContentType = "text/html; charset=utf-8";
                await http.Response.WriteAsync(
                    FederatedPassiveSecurityTokenServiceOperations.WriteErrorPage(
                        "Access Denied",
                        "The requested relying party is not authorized to use this authentication service.",
                        $"The relying party '{realmHostPort}' is not in the list of allowed relying parties.",
                        correlationId));
                return;
            }

            logger.LogInformation("Relying party validated: {RealmHost}", realmHostPort);

            // Explicitly run the Certificate authentication scheme.
            // The endpoint isn't marked RequireAuthorization (so we control the error UX),
            // which means we must trigger the cert handler ourselves.
            var authResult = await http.AuthenticateAsync(
                CertificateAuthenticationDefaults.AuthenticationScheme);

            if (!authResult.Succeeded || authResult.Principal?.Identity?.IsAuthenticated != true)
            {
                var failureReason = authResult.Failure?.Message
                    ?? (http.Connection.ClientCertificate == null
                        ? "No client certificate was presented."
                        : "Client certificate was rejected by validation.");

                logger.LogWarning(
                    "Authentication failed [CorrelationId: {CorrelationId}]: {Reason}",
                    correlationId, failureReason);

                http.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                http.Response.ContentType = "text/html; charset=utf-8";
                await http.Response.WriteAsync(
                    FederatedPassiveSecurityTokenServiceOperations.WriteErrorPage(
                        "Authentication Failed",
                        "Your client certificate could not be validated.",
                        failureReason,
                        correlationId));
                return;
            }

            // Promote the authenticated principal so http.User reflects the cert identity
            http.User = authResult.Principal;

            logger.LogInformation("User authenticated: {UserName}", http.User.Identity?.Name ?? "(unknown)");

            // Process certificate and build claims
            var cert = http.Connection.ClientCertificate;
            ClaimsIdentity? outputIdentity = null;

            if (cert != null)
            {
                try
                {
                    logger.LogDebug("Client certificate: Subject={Subject}, Issuer={Issuer}, Thumbprint={Thumbprint}",
                        cert.Subject, cert.Issuer, cert.Thumbprint);

                    // ADDITIONAL VALIDATION: Perform comprehensive certificate validation
                    logger.LogInformation("Performing additional certificate validation...");
                    var validationResult = CertValidators.ValidateCertificate(cert, validationOptions, logger);

                    if (!validationResult.IsValid)
                    {
                        var errors = string.Join("; ", validationResult.Errors);
                        logger.LogWarning("Certificate validation failed: {Errors} [CorrelationId: {CorrelationId}]", 
                            errors, correlationId);
                        
                        http.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                        http.Response.ContentType = "text/html; charset=utf-8";
                        await http.Response.WriteAsync(
                            FederatedPassiveSecurityTokenServiceOperations.WriteErrorPage(
                                "Certificate Validation Failed",
                                "Your client certificate did not pass security validation requirements.",
                                errors,
                                correlationId));
                        return;
                    }

                    logger.LogInformation("Certificate passed all validation checks");

                    // Check if UPN was extracted from SAN during validation
                    if (!string.IsNullOrEmpty(validationResult.ExtractedUpn))
                    {
                        logger.LogInformation("UPN extracted from certificate SAN: {Upn}", validationResult.ExtractedUpn);
                    }

                    var environment = configuration["Environment"];
                    logger.LogInformation("Environment configuration: {Environment}", environment ?? "(not set - defaulting to SIPR)");
                    
                    CertProcessor? processor = null;

                    try
                    {
                        if (environment == "NIPR")
                        {
                            logger.LogDebug("Selecting NIPR certificate processor");
                            var certProcessor = http.RequestServices.GetRequiredService<DoDNIPRCertProcessor>();
                            var fallback = http.RequestServices.GetRequiredService<DefaultCertProcessor>();
                            processor = certProcessor.IsProvider(cert) ? certProcessor : fallback;
                            logger.LogInformation("Selected processor: {ProcessorType}", processor.GetType().Name);
                        }
                        else
                        {
                            logger.LogDebug("Selecting SIPR certificate processor");
                            var certProcessor = http.RequestServices.GetRequiredService<DoDSIPRCertProcessor>();
                            var fallback = http.RequestServices.GetRequiredService<DefaultCertProcessor>();
                            processor = certProcessor.IsProvider(cert) ? certProcessor : fallback;
                            logger.LogInformation("Selected processor: {ProcessorType}", processor.GetType().Name);
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Failed to instantiate certificate processor - will use fallback claims");
                        processor = null;
                    }

                    if (processor != null)
                    {
                        try
                        {
                            outputIdentity = new ClaimsIdentity(
                                authenticationType: "Certificate",
                                nameType: ClaimTypes.Upn,
                                roleType: ClaimTypes.Role);

                            processor.ProcessDefaults(cert);
                            processor.ProcessCert(cert, ref outputIdentity);
                            
                            var claimCount = outputIdentity?.Claims?.Count() ?? 0;
                            logger.LogInformation("Certificate processing complete. Generated {ClaimCount} claims", claimCount);
                            

                            if (claimCount > 0)
                            {
                                var upnClaim = outputIdentity!.Claims.FirstOrDefault(c =>
                                    c.Type == ClaimTypes.Upn ||
                                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn");

                                logger.LogInformation("Identity Name will be: {IdentityName} (from UPN claim)",
                                    upnClaim?.Value ?? "(not found)");

                                foreach (var claim in outputIdentity!.Claims)
                                {
                                    logger.LogDebug("Claim: {Type} = {Value}", claim.Type, claim.Value);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            logger.LogError(ex, "Certificate processing failed - will use fallback claims");
                            outputIdentity = null;
                        }
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Unexpected error during certificate claim extraction - will use fallback claims");
                    outputIdentity = null;
                }
            }
            else
            {
                logger.LogWarning("No client certificate present in connection");
            }

            // Use processed identity or fall back to authenticated user
            ClaimsPrincipal claimsPrincipal;
            
            try
            {
                claimsPrincipal = outputIdentity?.Claims.Any() ?? false
                    ? new ClaimsPrincipal(outputIdentity)
                    : http.User ?? new ClaimsPrincipal();

                // Remove null or empty claim values
                if (claimsPrincipal.Identity is ClaimsIdentity identity)
                {
                    try
                    {
                        var claimsToRemove = identity.Claims
                            .Where(c => string.IsNullOrWhiteSpace(c.Value))
                            .ToList();

                        foreach (var claim in claimsToRemove)
                        {
                            identity.RemoveClaim(claim);
                        }

                        if (claimsToRemove.Any())
                        {
                            logger.LogInformation("Removed {Count} claims with null or empty values", claimsToRemove.Count);
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogWarning(ex, "Failed to remove empty claims - continuing with all claims");
                    }
                }

                logger.LogInformation("ClaimsPrincipal.Identity.Name = {Name}",
                    claimsPrincipal?.Identity?.Name ?? "(null)");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to create ClaimsPrincipal - using authenticated user as fallback");
                claimsPrincipal = http.User ?? new ClaimsPrincipal();
            }

            // Generate token response
            logger.LogInformation("Processing sign-in request for wtrealm={WTrealm}, wreply={WReply}", 
                requestMessage.Wtrealm, requestMessage.Wreply ?? "(none)");

            WsFederationMessage responseMessage;
            try
            {
                responseMessage = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(
                    requestMessage,
                    claimsPrincipal,
                    sts,
                    logger);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "CRITICAL: Failed to generate security token [CorrelationId: {CorrelationId}]", correlationId);
                http.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                http.Response.ContentType = "text/html; charset=utf-8";
                await http.Response.WriteAsync(
                    FederatedPassiveSecurityTokenServiceOperations.WriteErrorPage(
                        "Token Generation Failed",
                        "We were unable to generate your security token. This issue has been logged.",
                        ex.Message,
                        correlationId));
                return;
            }

            // Log response message details
            logger.LogInformation("Response created - Wreply={Wreply}, ParameterCount={Count}",
                responseMessage.Wreply ?? "(null)",
                responseMessage.Parameters?.Count ?? 0);

            // Log the actual POST URL
            var postUrl = responseMessage.Wreply;
            if (string.IsNullOrEmpty(postUrl))
            {
                if (responseMessage.Parameters != null)
                {
                    responseMessage.Parameters.TryGetValue(WsFederationConstants.WsFederationParameterNames.Wtrealm, out postUrl);
                }
            }
            logger.LogInformation("Token will be posted to: {PostUrl}", postUrl ?? "(NULL - ERROR!)");

            if (string.IsNullOrEmpty(postUrl))
            {
                logger.LogError("CRITICAL: No POST URL available! wreply and wtrealm are both null/empty [CorrelationId: {CorrelationId}]", 
                    correlationId);
            }

            string html;
            try
            {
                html = responseMessage.WriteFormPost(logger);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "CRITICAL: Failed to generate form POST HTML [CorrelationId: {CorrelationId}]", correlationId);
                http.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                http.Response.ContentType = "text/html; charset=utf-8";
                await http.Response.WriteAsync(
                    FederatedPassiveSecurityTokenServiceOperations.WriteErrorPage(
                        "Response Generation Failed",
                        "We were unable to generate the authentication response.",
                        ex.Message,
                        correlationId));
                return;
            }

            logger.LogInformation("Sending WS-Fed response form to client. Response length: {Length} bytes", html.Length);
            logger.LogInformation("========== REQUEST COMPLETE ==========");

            http.Response.ContentType = "text/html; charset=utf-8";
            await http.Response.WriteAsync(html);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "FATAL: Unhandled exception in /wsfed endpoint [CorrelationId: {CorrelationId}]", correlationId);
            
            if (!http.Response.HasStarted)
            {
                http.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                http.Response.ContentType = "text/html; charset=utf-8";
                await http.Response.WriteAsync(
                    FederatedPassiveSecurityTokenServiceOperations.WriteErrorPage(
                        "Authentication Failed",
                        "We were unable to complete your authentication request. This issue has been logged and will be investigated.",
                        ex.Message,
                        correlationId));
            }
        }
    })
    .AllowAnonymous(); // Endpoint performs its own certificate authentication via AuthenticateAsync

    static string GenerateFederationMetadata(
        string entityId,
        string passiveEndpoint,
        string orgName,
        string orgDisplayName,
        string orgUrl,
        string[] supportedClaims,
        X509Certificate2? signingCert)
    {
        var escapedEntityId = System.Security.SecurityElement.Escape(entityId) ?? entityId;
        var escapedPassiveEndpoint = System.Security.SecurityElement.Escape(passiveEndpoint) ?? passiveEndpoint;
        var escapedOrgName = System.Security.SecurityElement.Escape(orgName) ?? orgName;
        var escapedOrgDisplayName = System.Security.SecurityElement.Escape(orgDisplayName) ?? orgDisplayName;
        var escapedOrgUrl = System.Security.SecurityElement.Escape(orgUrl) ?? orgUrl;

        var sb = new StringBuilder();
        sb.AppendLine(@"<?xml version=""1.0"" encoding=""utf-8""?>");
        sb.AppendLine($@"<EntityDescriptor entityID=""{escapedEntityId}"" xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"">");
        
        // SecurityTokenServiceType (STS Role Descriptor)
        sb.AppendLine($@"  <RoleDescriptor xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"">");
        
        // Signing Certificate KeyDescriptor
        if (signingCert != null)
        {
            var certBase64 = Convert.ToBase64String(signingCert.Export(X509ContentType.Cert));
            sb.AppendLine($@"    <KeyDescriptor use=""signing"">");
            sb.AppendLine($@"      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">");
            sb.AppendLine($@"        <X509Data>");
            sb.AppendLine($@"          <X509Certificate>{certBase64}</X509Certificate>");
            sb.AppendLine($@"        </X509Data>");
            sb.AppendLine($@"      </KeyInfo>");
            sb.AppendLine($@"    </KeyDescriptor>");
        }

        // Passive Requestor Endpoint
        sb.AppendLine($@"    <fed:PassiveRequestorEndpoint>");
        sb.AppendLine($@"      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">");
        sb.AppendLine($@"        <wsa:Address>{escapedPassiveEndpoint}</wsa:Address>");
        sb.AppendLine($@"      </wsa:EndpointReference>");
        sb.AppendLine($@"    </fed:PassiveRequestorEndpoint>");

        // Supported Token Types
        sb.AppendLine($@"    <fed:TokenTypesOffered>");
        sb.AppendLine($@"      <fed:TokenType Uri=""urn:oasis:names:tc:SAML:1.0:assertion"" />");
        sb.AppendLine($@"      <fed:TokenType Uri=""urn:oasis:names:tc:SAML:2.0:assertion"" />");
        sb.AppendLine($@"    </fed:TokenTypesOffered>");

        // Supported Claim Types
        if (supportedClaims.Any())
        {
            sb.AppendLine($@"    <fed:ClaimTypesOffered>");
            foreach (var claimType in supportedClaims)
            {
                var escapedClaimType = System.Security.SecurityElement.Escape(claimType) ?? claimType;
                var claimName = claimType.Contains('/') ? claimType.Substring(claimType.LastIndexOf('/') + 1) : claimType;
                var escapedClaimName = System.Security.SecurityElement.Escape(claimName) ?? claimName;
                
                sb.AppendLine($@"      <auth:ClaimType Uri=""{escapedClaimType}"" Optional=""true"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"">");
                sb.AppendLine($@"        <auth:DisplayName>{escapedClaimName}</auth:DisplayName>");
                sb.AppendLine($@"      </auth:ClaimType>");
            }
            sb.AppendLine($@"    </fed:ClaimTypesOffered>");
        }

        sb.AppendLine($@"  </RoleDescriptor>");

        // Organization Info
        sb.AppendLine($@"  <Organization>");
        sb.AppendLine($@"    <OrganizationName xml:lang=""en"">{escapedOrgName}</OrganizationName>");
        sb.AppendLine($@"    <OrganizationDisplayName xml:lang=""en"">{escapedOrgDisplayName}</OrganizationDisplayName>");
        sb.AppendLine($@"    <OrganizationURL xml:lang=""en"">{escapedOrgUrl}</OrganizationURL>");
        sb.AppendLine($@"  </Organization>");

        sb.AppendLine($@"</EntityDescriptor>");

        return sb.ToString();
    }

    Log.Information("Mini-STS application configured and ready");
    Log.Information("Listening for requests...");
    
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
    throw;
}
finally
{
    Log.Information("Application shutting down");
    Log.CloseAndFlush();
}