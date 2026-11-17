using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace Services
{
    public class SecurityTokenService
    {
        private readonly X509Certificate2 _signingCertificate;
        private readonly string _issuer;
        private readonly TimeSpan _tokenLifetime;
        private readonly ILogger<SecurityTokenService>? _logger;

        public TimeSpan TokenLifetime => _tokenLifetime;

        public SecurityTokenService(
            X509Certificate2 signingCertificate,
            string issuer,
            TimeSpan tokenLifetime,
            ILogger<SecurityTokenService>? logger = null)
        {
            _signingCertificate = signingCertificate ?? throw new ArgumentNullException(nameof(signingCertificate));
            _issuer = issuer;
            _tokenLifetime = tokenLifetime;
            _logger = logger;

            if (!_signingCertificate.HasPrivateKey)
                throw new ArgumentException("Signing certificate must have a private key.");
        }

        public string IssueToken(ClaimsPrincipal principal, string appliesTo)
        {
            // Get subject name with proper priority: UPN > Name > NameIdentifier > Email
            var subjectName =
                principal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")?.Value
                ?? principal.FindFirst(ClaimTypes.Upn)?.Value
                ?? principal.Identity?.Name
                ?? principal.FindFirst(ClaimTypes.Name)?.Value
                ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                ?? principal.FindFirst(ClaimTypes.Email)?.Value
                ?? "unknown";

            _logger?.LogDebug("IssueToken: Issuing token for subject={Subject} (from principal {PrincipalIdentityName}) to {AppliesTo}",
                subjectName, principal.Identity?.Name ?? "(null)", appliesTo);

            var now = DateTime.UtcNow;
            var expires = now.Add(_tokenLifetime);

            // Filter claims
            var claims = principal.Claims
                .Where(c => !string.IsNullOrEmpty(c.Type) && !string.IsNullOrWhiteSpace(c.Value))
                .ToList();

            _logger?.LogDebug("IssueToken: Processing {ClaimCount} claims", claims.Count);

            // Build the assertion XML manually
            var assertionXml = BuildSamlAssertion(appliesTo, now, expires, claims);

            // Sign the Assertion
            var signedAssertionXml = SignAssertion(assertionXml);

            _logger?.LogInformation("IssueToken: Token issued successfully for subject={Subject}", subjectName);
            return signedAssertionXml;
        }

        private string BuildSamlAssertion(string appliesTo, DateTime notBefore, DateTime notOnOrAfter, List<Claim> claims)
        {
            var assertionId = "_" + Guid.NewGuid().ToString("D");
            var issueInstant = XmlConvert.ToString(DateTime.UtcNow, XmlDateTimeSerializationMode.Utc);
            var notBeforeStr = XmlConvert.ToString(notBefore, XmlDateTimeSerializationMode.Utc);
            var notOnOrAfterStr = XmlConvert.ToString(notOnOrAfter, XmlDateTimeSerializationMode.Utc);
            var escapedAppliesTo = System.Security.SecurityElement.Escape(appliesTo) ?? appliesTo;
            var escapedIssuer = System.Security.SecurityElement.Escape(_issuer) ?? _issuer;

            // Get the UPN for the NameIdentifier - with fallback
            string upn = "unknown";
            try
            {
                upn = claims.FirstOrDefault(c => 
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" ||
                    c.Type == ClaimTypes.Upn)?.Value ?? "unknown";
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to extract UPN claim - using 'unknown'");
            }
            
            var escapedUpn = System.Security.SecurityElement.Escape(upn) ?? upn;

            // If no email claim exists, add one with the UPN value
            try
            {
                var hasEmailClaim = claims.Any(c => 
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ||
                    c.Type == ClaimTypes.Email);

                if (!hasEmailClaim && upn != "unknown")
                {
                    _logger?.LogDebug("No email claim found, adding email claim with UPN value: {Upn}", upn);
                    claims.Add(new Claim(ClaimTypes.Email, upn));
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to add email claim - continuing without it");
            }

            var sb = new StringBuilder();
            sb.AppendLine($@"<saml:Assertion MajorVersion=""1"" MinorVersion=""1"" AssertionID=""{assertionId}"" Issuer=""{escapedIssuer}"" IssueInstant=""{issueInstant}"" xmlns:saml=""urn:oasis:names:tc:SAML:1.0:assertion"">");
            
            // Conditions
            sb.AppendLine($@"  <saml:Conditions NotBefore=""{notBeforeStr}"" NotOnOrAfter=""{notOnOrAfterStr}"">");
            sb.AppendLine($@"    <saml:AudienceRestrictionCondition>");
            sb.AppendLine($@"      <saml:Audience>{escapedAppliesTo}</saml:Audience>");
            sb.AppendLine($@"    </saml:AudienceRestrictionCondition>");
            sb.AppendLine($@"  </saml:Conditions>");

            // AttributeStatement
            if (claims.Any())
            {
                sb.AppendLine($@"  <saml:AttributeStatement>");
                
                // Subject with NameIdentifier (UPN) and SubjectConfirmation
                sb.AppendLine($@"    <saml:Subject>");
                sb.AppendLine($@"      <saml:NameIdentifier>{escapedUpn}</saml:NameIdentifier>");
                sb.AppendLine($@"      <saml:SubjectConfirmation>");
                sb.AppendLine($@"        <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>");
                sb.AppendLine($@"      </saml:SubjectConfirmation>");
                sb.AppendLine($@"    </saml:Subject>");

                // Attributes grouped by claim type - WITH error resilience
                foreach (var claimGroup in claims.GroupBy(c => c.Type))
                {
                    try
                    {
                        // Extract just the claim name from the full URI
                        var claimType = claimGroup.Key;
                        string attributeName;
                        
                        try
                        {
                            // Parse the claim type to get just the name part
                            if (claimType.Contains('/'))
                            {
                                attributeName = claimType.Substring(claimType.LastIndexOf('/') + 1);
                            }
                            else
                            {
                                attributeName = claimType;
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger?.LogWarning(ex, "Failed to parse claim type, using full type: {ClaimType}", claimType);
                            attributeName = claimType;
                        }
                        
                        var escapedAttributeName = System.Security.SecurityElement.Escape(attributeName) ?? attributeName;
                        
                        sb.AppendLine($@"    <saml:Attribute AttributeName=""{escapedAttributeName}"" AttributeNamespace=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims"">");
                        
                        foreach (var claim in claimGroup)
                        {
                            try
                            {
                                var escapedValue = System.Security.SecurityElement.Escape(claim.Value) ?? claim.Value;
                                sb.AppendLine($@"      <saml:AttributeValue>{escapedValue}</saml:AttributeValue>");
                            }
                            catch (Exception ex)
                            {
                                _logger?.LogWarning(ex, "Failed to add claim value for {ClaimType} - skipping", claimType);
                            }
                        }
                        
                        sb.AppendLine($@"    </saml:Attribute>");

                        _logger?.LogDebug("  Claim: {Type} -> AttributeName={AttributeName}, Values={Values}",
                            claimGroup.Key,
                            attributeName,
                            string.Join(", ", claimGroup.Select(c => c.Value)));
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning(ex, "Failed to process claim group {ClaimType} - skipping", claimGroup.Key);
                    }
                }

                sb.AppendLine($@"  </saml:AttributeStatement>");
            }

            // AuthenticationStatement with NameIdentifier
            sb.AppendLine($@"  <saml:AuthenticationStatement AuthenticationMethod=""urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"" AuthenticationInstant=""{issueInstant}"">");
            sb.AppendLine($@"    <saml:Subject>");
            sb.AppendLine($@"      <saml:NameIdentifier>{escapedUpn}</saml:NameIdentifier>");
            sb.AppendLine($@"      <saml:SubjectConfirmation>");
            sb.AppendLine($@"        <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>");
            sb.AppendLine($@"      </saml:SubjectConfirmation>");
            sb.AppendLine($@"    </saml:Subject>");
            sb.AppendLine($@"  </saml:AuthenticationStatement>");

            sb.AppendLine($@"</saml:Assertion>");

            _logger?.LogInformation("Built SAML assertion with NameIdentifier (UPN): {Upn}", upn);

            return sb.ToString();
        }

        private string SignAssertion(string assertionXml)
        {
            try
            {
                var doc = new XmlDocument { PreserveWhitespace = true };
                doc.LoadXml(assertionXml);

                var assertionElement = doc.DocumentElement;
                if (assertionElement == null)
                    throw new InvalidOperationException("Invalid assertion XML - no root element");

                // Get the AssertionID
                var assertionId = assertionElement.GetAttribute("AssertionID");
                if (string.IsNullOrEmpty(assertionId))
                {
                    throw new InvalidOperationException("Assertion missing AssertionID attribute");
                }

                _logger?.LogDebug("SignAssertion: Signing assertion with ID={AssertionId}", assertionId);

                // WORKAROUND: Create a custom SignedXml that can resolve AssertionID
                var signedXml = new AssertionSignedXml(doc, assertionId);
                var privateKey = _signingCertificate.GetRSAPrivateKey()
                    ?? throw new InvalidOperationException("No RSA private key available.");

                signedXml.SigningKey = privateKey;

                // Create reference to the Assertion
                var reference = new System.Security.Cryptography.Xml.Reference("#" + assertionId)
                {
                    DigestMethod = System.Security.Cryptography.Xml.SignedXml.XmlDsigSHA256Url
                };

                // Add transforms
                reference.AddTransform(new System.Security.Cryptography.Xml.XmlDsigEnvelopedSignatureTransform());
                reference.AddTransform(new System.Security.Cryptography.Xml.XmlDsigExcC14NTransform());

                signedXml.AddReference(reference);

                // CRITICAL FIX: Add KeyInfo with X509Data containing the full certificate
                // ADFS needs the full certificate in the signature to verify it
                var keyInfo = new System.Security.Cryptography.Xml.KeyInfo();
                var x509Data = new System.Security.Cryptography.Xml.KeyInfoX509Data();
                
                // Add the full certificate (not just issuer/serial)
                x509Data.AddCertificate(_signingCertificate);
                
                keyInfo.AddClause(x509Data);
                signedXml.KeyInfo = keyInfo;

                // Set signature and canonicalization methods
                if (signedXml.SignedInfo != null)
                {
                    signedXml.SignedInfo.SignatureMethod = System.Security.Cryptography.Xml.SignedXml.XmlDsigRSASHA256Url;
                    signedXml.SignedInfo.CanonicalizationMethod = System.Security.Cryptography.Xml.SignedXml.XmlDsigExcC14NTransformUrl;
                }
                
                // Compute signature
                signedXml.ComputeSignature();

                // Insert signature as last child of Assertion (after all statements)
                var signatureElement = signedXml.GetXml();
                assertionElement.AppendChild(doc.ImportNode(signatureElement, true));

                _logger?.LogDebug("SignAssertion: Assertion signed successfully");
                _logger?.LogDebug("Certificate Subject: {Subject}, Thumbprint: {Thumbprint}", 
                    _signingCertificate.Subject, _signingCertificate.Thumbprint);

                return doc.OuterXml;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to sign assertion");
                throw;
            }
        }

        // Custom SignedXml class that can resolve SAML 1.1 AssertionID references
        private class AssertionSignedXml : System.Security.Cryptography.Xml.SignedXml
        {
            private readonly string _assertionId;

            public AssertionSignedXml(XmlDocument document, string assertionId) : base(document)
            {
                _assertionId = assertionId;
            }

            public override XmlElement? GetIdElement(XmlDocument document, string idValue)
            {
                // First try the default resolution
                var elem = base.GetIdElement(document, idValue);
                if (elem != null)
                    return elem;

                // If not found and it matches our assertion ID, find by AssertionID attribute
                if (idValue == _assertionId)
                {
                    var nsManager = new XmlNamespaceManager(document.NameTable);
                    nsManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:1.0:assertion");
                    
                    // Try to find element with AssertionID attribute matching the value
                    var node = document.SelectSingleNode($"//*[@AssertionID='{idValue}']", nsManager);
                    return node as XmlElement;
                }

                return null;
            }
        }
    }
}