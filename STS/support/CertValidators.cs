using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace FSCA.Support
{
    public static class CertValidators
    {
        /// <summary>
        /// Validates certificate chain trust and revocation status
        /// </summary>
        public static bool IsChainValid(X509Certificate2 cert, ILogger? logger = null)
        {
            try
            {
                using (var chain = new X509Chain())
                {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                    chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(15);
                    
                    var isValid = chain.Build(cert);
                    
                    if (!isValid && logger != null)
                    {
                        foreach (var status in chain.ChainStatus)
                        {
                            logger.LogWarning("Chain validation error: {Status} - {StatusInfo}", 
                                status.Status, status.StatusInformation);
                        }
                    }
                    
                    return isValid;
                }
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Exception during chain validation for certificate {Subject}", cert.Subject);
                return false;
            }
        }

        /// <summary>
        /// Validates certificate has Client Authentication EKU (1.3.6.1.5.5.7.3.2)
        /// </summary>
        public static bool HasClientAuthEku(X509Certificate2 cert, ILogger? logger = null)
        {
            var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (eku == null)
            {
                logger?.LogWarning("Certificate has no Enhanced Key Usage extension: {Subject}", cert.Subject);
                return false;
            }

            foreach (var oid in eku.EnhancedKeyUsages)
            {
                if (oid.Value == "1.3.6.1.5.5.7.3.2") // Client Authentication EKU
                    return true;
            }
            
            logger?.LogWarning("Certificate missing Client Authentication EKU: {Subject}", cert.Subject);
            return false;
        }

        /// <summary>
        /// Validates certificate has Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2) - Required for CAC/PIV
        /// </summary>
        public static bool HasSmartCardLogonEku(X509Certificate2 cert, ILogger? logger = null)
        {
            var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (eku == null) return false;

            foreach (var oid in eku.EnhancedKeyUsages)
            {
                if (oid.Value == "1.3.6.1.4.1.311.20.2.2") // Smart Card Logon
                    return true;
            }
            
            logger?.LogDebug("Certificate missing Smart Card Logon EKU: {Subject}", cert.Subject);
            return false;
        }

        /// <summary>
        /// Validates certificate is issued by a DoD Root CA
        /// </summary>
        public static bool IsIssuedByDoDCA(X509Certificate2 cert, ILogger? logger = null)
        {
            var issuer = cert.Issuer.ToUpperInvariant();
            
            // Check for DoD PKI CA issuers
            var dodIssuers = new[]
            {
                "DOD ROOT CA",
                "DOD EMAIL CA",
                "DOD ID CA",
                "DOD SW CA",
                "DOD ID SW CA"
            };

            var isDoD = dodIssuers.Any(dod => issuer.Contains(dod));
            
            if (!isDoD)
            {
                logger?.LogDebug("Certificate not issued by DoD CA. Issuer: {Issuer}", cert.Issuer);
            }
            
            return isDoD;
        }

        /// <summary>
        /// Validates certificate has required Key Usage flags for authentication
        /// Typically: Digital Signature and/or Key Encipherment
        /// </summary>
        public static bool HasRequiredKeyUsage(X509Certificate2 cert, ILogger? logger = null)
        {
            var keyUsage = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (keyUsage == null)
            {
                logger?.LogWarning("Certificate has no Key Usage extension: {Subject}", cert.Subject);
                return false;
            }

            var hasDigitalSignature = keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature);
            var hasKeyEncipherment = keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment);

            if (!hasDigitalSignature && !hasKeyEncipherment)
            {
                logger?.LogWarning("Certificate missing required Key Usage (Digital Signature or Key Encipherment): {Subject}", cert.Subject);
                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates certificate Subject Alternative Name (SAN) contains a UPN
        /// </summary>
        public static bool HasUpnInSan(X509Certificate2 cert, out string? upn, ILogger? logger = null)
        {
            upn = null;
            
            var san = cert.Extensions.OfType<X509Extension>()
                .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17"); // Subject Alternative Name OID

            if (san == null)
            {
                logger?.LogDebug("Certificate has no Subject Alternative Name extension: {Subject}", cert.Subject);
                return false;
            }

            var sanData = san.Format(false);
            
            // Look for UPN (User Principal Name) which typically follows "Other Name:Principal Name="
            var upnMarker = "Principal Name=";
            var upnIndex = sanData.IndexOf(upnMarker, StringComparison.OrdinalIgnoreCase);
            
            if (upnIndex >= 0)
            {
                var startIndex = upnIndex + upnMarker.Length;
                var endIndex = sanData.IndexOfAny(new[] { ',', '\r', '\n' }, startIndex);
                
                upn = endIndex > startIndex 
                    ? sanData.Substring(startIndex, endIndex - startIndex).Trim()
                    : sanData.Substring(startIndex).Trim();
                
                logger?.LogDebug("Found UPN in SAN: {Upn} for certificate {Subject}", upn, cert.Subject);
                return true;
            }

            logger?.LogDebug("No UPN found in SAN for certificate: {Subject}", cert.Subject);
            return false;
        }

        /// <summary>
        /// Validates certificate is not self-signed
        /// </summary>
        public static bool IsNotSelfSigned(X509Certificate2 cert, ILogger? logger = null)
        {
            var isSelfSigned = cert.Subject.Equals(cert.Issuer, StringComparison.OrdinalIgnoreCase);
            
            if (isSelfSigned)
            {
                logger?.LogWarning("Certificate is self-signed: {Subject}", cert.Subject);
            }
            
            return !isSelfSigned;
        }

        /// <summary>
        /// Validates certificate validity period (not expired, not before valid date)
        /// </summary>
        public static bool IsWithinValidityPeriod(X509Certificate2 cert, ILogger? logger = null)
        {
            var now = DateTime.UtcNow;
            
            if (now < cert.NotBefore)
            {
                logger?.LogWarning("Certificate not yet valid. NotBefore: {NotBefore}, Current: {Now}, Subject: {Subject}", 
                    cert.NotBefore, now, cert.Subject);
                return false;
            }

            if (now > cert.NotAfter)
            {
                logger?.LogWarning("Certificate expired. NotAfter: {NotAfter}, Current: {Now}, Subject: {Subject}", 
                    cert.NotAfter, now, cert.Subject);
                return false;
            }

            // Warn if expiring soon (within 30 days)
            if ((cert.NotAfter - now).TotalDays < 30)
            {
                logger?.LogWarning("Certificate expiring soon: {DaysRemaining} days remaining. Subject: {Subject}", 
                    (cert.NotAfter - now).TotalDays, cert.Subject);
            }

            return true;
        }

        /// <summary>
        /// Validates certificate key strength (minimum 2048-bit RSA)
        /// </summary>
        public static bool HasMinimumKeyStrength(X509Certificate2 cert, int minimumBits = 2048, ILogger? logger = null)
        {
            try
            {
                var publicKey = cert.PublicKey;
                var keySize = publicKey.Key.KeySize;

                if (keySize < minimumBits)
                {
                    logger?.LogWarning("Certificate key size {KeySize} is below minimum {MinimumBits}. Subject: {Subject}", 
                        keySize, minimumBits, cert.Subject);
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to validate key strength for certificate: {Subject}", cert.Subject);
                return false;
            }
        }

        /// <summary>
        /// Validates certificate signature algorithm is secure (not MD5, SHA1)
        /// </summary>
        public static bool HasSecureSignatureAlgorithm(X509Certificate2 cert, ILogger? logger = null)
        {
            var algorithm = cert.SignatureAlgorithm.FriendlyName?.ToUpperInvariant() ?? string.Empty;
            
            // Reject weak algorithms
            var weakAlgorithms = new[] { "MD5", "SHA1", "SHA-1" };
            
            if (weakAlgorithms.Any(weak => algorithm.Contains(weak)))
            {
                logger?.LogWarning("Certificate uses weak signature algorithm: {Algorithm}. Subject: {Subject}", 
                    cert.SignatureAlgorithm.FriendlyName, cert.Subject);
                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates certificate is trusted in the machine's certificate store
        /// </summary>
        public static bool IsTrustedRoot(X509Certificate2 cert, ILogger? logger = null)
        {
            try
            {
                using (var chain = new X509Chain())
                {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // Just check trust, not revocation
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                    
                    if (!chain.Build(cert))
                        return false;

                    // Check if the root is in the trusted root store
                    var rootCert = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                    
                    using (var trustedStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
                    {
                        trustedStore.Open(OpenFlags.ReadOnly);
                        var trustedCerts = trustedStore.Certificates.Find(
                            X509FindType.FindByThumbprint, 
                            rootCert.Thumbprint, 
                            false);
                        
                        var isTrusted = trustedCerts.Count > 0;
                        
                        if (!isTrusted)
                        {
                            logger?.LogWarning("Certificate root is not in trusted store. Root: {RootSubject}", rootCert.Subject);
                        }
                        
                        return isTrusted;
                    }
                }
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to validate trusted root for certificate: {Subject}", cert.Subject);
                return false;
            }
        }

        /// <summary>
        /// Comprehensive validation combining multiple checks
        /// </summary>
        public static ValidationResult ValidateCertificate(
            X509Certificate2 cert, 
            ValidationOptions options, 
            ILogger? logger = null)
        {
            var result = new ValidationResult { IsValid = true };
            string? upn = null;

            if (options.ValidateChain && !IsChainValid(cert, logger))
            {
                result.IsValid = false;
                result.Errors.Add("Certificate chain validation failed");
            }

            if (options.RequireClientAuthEku && !HasClientAuthEku(cert, logger))
            {
                result.IsValid = false;
                result.Errors.Add("Certificate missing Client Authentication EKU");
            }

            if (options.RequireSmartCardLogonEku && !HasSmartCardLogonEku(cert, logger))
            {
                result.IsValid = false;
                result.Errors.Add("Certificate missing Smart Card Logon EKU");
            }

            if (options.RequireDoDIssuer && !IsIssuedByDoDCA(cert, logger))
            {
                result.IsValid = false;
                result.Errors.Add("Certificate not issued by DoD PKI CA");
            }

            if (options.ValidateKeyUsage && !HasRequiredKeyUsage(cert, logger))
            {
                result.IsValid = false;
                result.Errors.Add("Certificate missing required Key Usage");
            }

            if (options.ValidateValidityPeriod && !IsWithinValidityPeriod(cert, logger))
            {
                result.IsValid = false;
                result.Errors.Add("Certificate not within validity period");
            }

            if (options.RejectSelfSigned && !IsNotSelfSigned(cert, logger))
            {
                result.IsValid = false;
                result.Errors.Add("Self-signed certificates not allowed");
            }

            if (options.MinimumKeySize > 0 && !HasMinimumKeyStrength(cert, options.MinimumKeySize, logger))
            {
                result.IsValid = false;
                result.Errors.Add($"Certificate key size below minimum {options.MinimumKeySize} bits");
            }

            if (options.RequireSecureSignatureAlgorithm && !HasSecureSignatureAlgorithm(cert, logger))
            {
                result.IsValid = false;
                result.Errors.Add("Certificate uses weak signature algorithm");
            }

            if (options.RequireTrustedRoot && !IsTrustedRoot(cert, logger))
            {
                result.IsValid = false;
                result.Errors.Add("Certificate root not trusted");
            }

            if (options.RequireUpnInSan && !HasUpnInSan(cert, out upn, logger))
            {
                result.IsValid = false;
                result.Errors.Add("Certificate missing UPN in Subject Alternative Name");
            }
            else if (upn != null)
            {
                result.ExtractedUpn = upn;
            }

            return result;
        }
    }

    /// <summary>
    /// Options for certificate validation
    /// </summary>
    public class ValidationOptions
    {
        public bool ValidateChain { get; set; } = true;
        public bool RequireClientAuthEku { get; set; } = true;
        public bool RequireSmartCardLogonEku { get; set; } = false;
        public bool RequireDoDIssuer { get; set; } = false;
        public bool ValidateKeyUsage { get; set; } = true;
        public bool ValidateValidityPeriod { get; set; } = true;
        public bool RejectSelfSigned { get; set; } = true;
        public int MinimumKeySize { get; set; } = 2048;
        public bool RequireSecureSignatureAlgorithm { get; set; } = true;
        public bool RequireTrustedRoot { get; set; } = false;
        public bool RequireUpnInSan { get; set; } = false;
    }

    /// <summary>
    /// Result of certificate validation
    /// </summary>
    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
        public string? ExtractedUpn { get; set; }
    }
}
