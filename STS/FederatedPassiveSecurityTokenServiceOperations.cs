using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.WsFederation;
using System.Security.Claims;
using System.Xml;

namespace Services
{
    public static class FederatedPassiveSecurityTokenServiceOperations
    {
        public static WsFederationMessage ProcessSignInRequest(
            WsFederationMessage requestMessage,
            ClaimsPrincipal user,
            SecurityTokenService sts,
            ILogger? logger = null)
        {
            if (requestMessage == null)
                throw new ArgumentNullException(nameof(requestMessage));
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (sts == null)
                throw new ArgumentNullException(nameof(sts));

            // Get wtrealm from request
            var wtrealm = requestMessage.Wtrealm;
            if (string.IsNullOrEmpty(wtrealm))
            {
                logger?.LogError("Request message missing wtrealm parameter");
                throw new InvalidOperationException("Request message must contain wtrealm parameter");
            }

            logger?.LogDebug("ProcessSignInRequest: wtrealm={Wtrealm}, wreply={Wreply}", 
                wtrealm, requestMessage.Wreply ?? "(none)");

            // Issue the token (SAML assertion) - wtrealm is used AS-IS for AppliesTo/Audience
            string tokenXml;
            try
            {
                tokenXml = sts.IssueToken(user, wtrealm);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CRITICAL: Failed to issue token for wtrealm={Wtrealm}", wtrealm);
                throw; // This is critical - can't continue without a token
            }

            // Create timestamps using the configured token lifetime
            var created = DateTime.UtcNow;
            var expires = created.Add(sts.TokenLifetime);

            logger?.LogDebug("Token lifetime: {Created} to {Expires}", created, expires);

            // Build WS-Trust RequestSecurityTokenResponse - wtrealm is used AS-IS for AppliesTo
            string rstr;
            try
            {
                rstr = BuildRequestSecurityTokenResponse(tokenXml, wtrealm, created, expires);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to build RequestSecurityTokenResponse");
                throw;
            }

            // Determine reply URL for POST - this is where we transform to /adfs/ls/
            string wreply;
            try
            {
                wreply = requestMessage.Wreply;
                if (string.IsNullOrEmpty(wreply))
                {
                    wreply = TransformToAdfsPassiveEndpoint(wtrealm, logger);
                }
                else
                {
                    wreply = TransformToAdfsPassiveEndpoint(wreply, logger);
                }
            }
            catch (Exception ex)
            {
                logger?.LogWarning(ex, "Failed to transform URL - using wtrealm as-is");
                wreply = requestMessage.Wreply ?? wtrealm;
            }

            // Create response message
            var responseMessage = new WsFederationMessage
            {
                Wa = WsFederationConstants.WsFederationActions.SignIn,
                Wresult = rstr,
                Wctx = requestMessage.Wctx,
                Wreply = wreply
            };

            logger?.LogDebug("Response Wreply (POST URL) set to: {Wreply}", wreply);
            logger?.LogDebug("Token AppliesTo/Audience set to: {Wtrealm}", wtrealm);

            // Also set wtrealm in Parameters (kept as-is, not transformed)
            responseMessage.Parameters[WsFederationConstants.WsFederationParameterNames.Wtrealm] = wtrealm;

            return responseMessage;
        }

        /// <summary>
        /// Builds a WS-Trust RequestSecurityTokenResponse (single response, not collection).
        /// This matches the ADFS token format.
        /// The appliesTo parameter is used AS-IS for the Audience/AppliesTo in the token.
        /// </summary>
        private static string BuildRequestSecurityTokenResponse(
            string tokenXml,
            string appliesTo,
            DateTime created,
            DateTime expires)
        {
            var createdStr = XmlConvert.ToString(created, XmlDateTimeSerializationMode.Utc);
            var expiresStr = XmlConvert.ToString(expires, XmlDateTimeSerializationMode.Utc);
            var escapedAppliesTo = System.Security.SecurityElement.Escape(appliesTo) ?? appliesTo;

            // WS-Trust format - single RequestSecurityTokenResponse
            // AppliesTo uses the wtrealm AS-IS (not transformed)
            return $@"<t:RequestSecurityTokenResponse xmlns:t=""http://schemas.xmlsoap.org/ws/2005/02/trust"">
  <t:Lifetime>
    <wsu:Created xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">{createdStr}</wsu:Created>
    <wsu:Expires xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">{expiresStr}</wsu:Expires>
  </t:Lifetime>
  <wsp:AppliesTo xmlns:wsp=""http://schemas.xmlsoap.org/ws/2004/09/policy"">
    <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
      <wsa:Address>{escapedAppliesTo}</wsa:Address>
    </wsa:EndpointReference>
  </wsp:AppliesTo>
  <t:RequestedSecurityToken>
{tokenXml}
  </t:RequestedSecurityToken>
  <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
  <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
  <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
</t:RequestSecurityTokenResponse>";
        }

        /// <summary>
        /// Transforms any URL with ADFS host to use the passive endpoint /adfs/ls/ for POST target only.
        /// This does NOT affect the wtrealm/AppliesTo/Audience in the token.
        /// </summary>
        private static string TransformToAdfsPassiveEndpoint(string url, ILogger? logger = null)
        {
            if (string.IsNullOrEmpty(url))
                return url;

            try
            {
                // Try to parse as URI - if it's a URN (like urn:sharepoint:poc), this will fail
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                {
                    // Not a valid absolute URI (probably a URN) - can't transform
                    logger?.LogDebug("URL is not a valid absolute URI (possibly URN), cannot transform: {Url}", url);
                    return url;
                }

                // Only transform if it's an HTTP/HTTPS URL with /adfs/ in the path
                if ((uri.Scheme == "http" || uri.Scheme == "https") && 
                    uri.AbsolutePath.Contains("/adfs/", StringComparison.OrdinalIgnoreCase))
                {
                    logger?.LogInformation("Transforming URL to ADFS passive endpoint for POST: {OriginalUrl}", url);
                    
                    // Replace any ADFS path with /adfs/ls/
                    var builder = new UriBuilder(uri)
                    {
                        Path = "/adfs/ls/",
                        Query = string.Empty // Clear query string for passive endpoint
                    };
                    
                    var transformed = builder.Uri.ToString();
                    logger?.LogInformation("Transformed POST URL to ADFS passive endpoint: {TransformedUrl}", transformed);
                    
                    return transformed;
                }

                logger?.LogDebug("URL does not need transformation, returning as-is: {Url}", url);
                return url;
            }
            catch (Exception ex)
            {
                logger?.LogWarning(ex, "Failed to transform URL, returning original: {Url}", url);
                return url;
            }
        }

        public static string WriteFormPost(this WsFederationMessage message, ILogger? logger = null)
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            logger?.LogDebug("WriteFormPost: Wreply={Wreply}, Parameters.Count={Count}", 
                message.Wreply ?? "(null)", 
                message.Parameters?.Count ?? 0);

            // Log all parameters for debugging
            if (message.Parameters != null)
            {
                foreach (var param in message.Parameters)
                {
                    logger?.LogDebug("  Parameter: {Key} = {Value}", param.Key, param.Value);
                }
            }

            // Determine the POST target: wreply if present, otherwise transform wtrealm to /adfs/ls/
            string postUrl;
            if (!string.IsNullOrEmpty(message.Wreply))
            {
                postUrl = message.Wreply;
                logger?.LogInformation("Using wreply as POST URL: {PostUrl}", postUrl);
            }
            else if (message.Parameters != null && message.Parameters.TryGetValue(WsFederationConstants.WsFederationParameterNames.Wtrealm, out var realm))
            {
                // Transform wtrealm to ADFS passive endpoint for POST
                postUrl = TransformToAdfsPassiveEndpoint(realm, logger);
                logger?.LogInformation("Using transformed wtrealm as POST URL: {PostUrl}", postUrl);
            }
            else
            {
                logger?.LogError("Response message missing both wreply and wtrealm");
                throw new InvalidOperationException("Response message must contain either wreply or wtrealm parameter");
            }

            var encodedWresult = System.Net.WebUtility.HtmlEncode(message.Wresult);
            var encodedWctx = System.Net.WebUtility.HtmlEncode(message.Wctx);
            var encodedAction = System.Net.WebUtility.HtmlEncode(postUrl);

            logger?.LogInformation("Generating form POST to {PostUrl}, wresult length={Length}", 
                postUrl, message.Wresult?.Length ?? 0);

            return $@"<!doctype html>
<html>
  <head>
    <meta charset=""utf-8"">
    <title>Signing in...</title>
    <style>
      body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
      .container {{ max-width: 600px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
      .spinner {{ border: 4px solid #f3f3f3; border-top: 4px solid #0078d4; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 20px; }}
      @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
      h1 {{ color: #333; font-size: 24px; margin: 0 0 10px; text-align: center; }}
      p {{ color: #666; text-align: center; margin: 0; }}
    </style>
  </head>
  <body>
    <div class=""container"">
      <div class=""spinner""></div>
      <h1>Signing you in...</h1>
      <p>Please wait while we complete your authentication.</p>
    </div>
    <form id=""f"" method=""post"" action=""{encodedAction}"">
      <input type=""hidden"" name=""wa"" value=""wsignin1.0"" />
      <input type=""hidden"" name=""wresult"" value=""{encodedWresult}"" />
      <input type=""hidden"" name=""wctx"" value=""{encodedWctx}"" />
      <noscript>
        <div class=""container"" style=""margin-top: 20px; background: #fff3cd; border-left: 4px solid #ffc107;"">
          <p style=""color: #856404; font-weight: bold;"">JavaScript is required</p>
          <p style=""color: #856404;"">Please enable JavaScript or click the button below to continue.</p>
          <button type=""submit"" style=""display: block; margin: 20px auto; padding: 10px 30px; background: #0078d4; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer;"">Continue</button>
        </div>
      </noscript>
    </form>
    <script>document.getElementById('f').submit();</script>
  </body>
</html>";
        }

        /// <summary>
        /// Generates a friendly error page for authentication failures.
        /// </summary>
        public static string WriteErrorPage(string errorTitle, string errorMessage, string? errorDetails = null, string? correlationId = null)
        {
            var escapedTitle = System.Net.WebUtility.HtmlEncode(errorTitle);
            var escapedMessage = System.Net.WebUtility.HtmlEncode(errorMessage);
            var escapedDetails = !string.IsNullOrEmpty(errorDetails) 
                ? System.Net.WebUtility.HtmlEncode(errorDetails) 
                : null;
            var escapedCorrelationId = !string.IsNullOrEmpty(correlationId)
                ? System.Net.WebUtility.HtmlEncode(correlationId)
                : null;

            var detailsSection = !string.IsNullOrEmpty(escapedDetails)
                ? $@"<div class=""details"">
          <p><strong>Technical Details:</strong></p>
          <p class=""code"">{escapedDetails}</p>
        </div>"
                : string.Empty;

            var correlationSection = !string.IsNullOrEmpty(escapedCorrelationId)
                ? $@"<p class=""correlation"">Error ID: {escapedCorrelationId}</p>"
                : string.Empty;

            return $@"<!doctype html>
<html>
  <head>
    <meta charset=""utf-8"">
    <title>Authentication Error</title>
    <style>
      body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
      .container {{ max-width: 700px; margin: 50px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
      .error-icon {{ width: 60px; height: 60px; margin: 0 auto 20px; background: #d32f2f; border-radius: 50%; display: flex; align-items: center; justify-content: center; }}
      .error-icon::before {{ content: '✕'; color: white; font-size: 36px; font-weight: bold; }}
      h1 {{ color: #d32f2f; font-size: 28px; margin: 0 0 15px; text-align: center; }}
      p {{ color: #666; text-align: center; margin: 0 0 20px; line-height: 1.6; }}
      .details {{ background: #f9f9f9; border-left: 4px solid #d32f2f; padding: 15px; margin: 20px 0; border-radius: 4px; }}
      .details p {{ text-align: left; margin: 5px 0; }}
      .code {{ font-family: 'Courier New', monospace; font-size: 13px; background: #fff; padding: 10px; border-radius: 4px; word-break: break-word; }}
      .correlation {{ font-size: 12px; color: #999; text-align: center; margin-top: 30px; font-family: 'Courier New', monospace; }}
      .actions {{ margin-top: 30px; text-align: center; }}
      .btn {{ display: inline-block; padding: 12px 30px; background: #0078d4; color: white; text-decoration: none; border-radius: 4px; font-weight: 500; margin: 0 5px; }}
      .btn:hover {{ background: #005a9e; }}
      .btn-secondary {{ background: #666; }}
      .btn-secondary:hover {{ background: #555; }}
    </style>
  </head>
  <body>
    <div class=""container"">
      <div class=""error-icon""></div>
      <h1>{escapedTitle}</h1>
      <p>{escapedMessage}</p>
      {detailsSection}
      <div class=""actions"">
        <a href=""javascript:history.back()"" class=""btn btn-secondary"">Go Back</a>
        <a href=""javascript:location.reload()"" class=""btn"">Try Again</a>
      </div>
      {correlationSection}
    </div>
  </body>
</html>";
        }
    }
}