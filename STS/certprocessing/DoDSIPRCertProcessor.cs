using FSCA.Support;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace FSCA.CertProcessing
{
    internal class DoDSIPRCertProcessor : DefaultCertProcessor
    {
        // Require ILogger<T> so DI will inject a real logger
        public DoDSIPRCertProcessor(IConfiguration config, ILogger<DoDSIPRCertProcessor> logger) : base(config, logger) { }

        public override string OU => "OU=DoD";

        personaType _PersonaType = personaType.ctr;

        enum personaType { mil, civ, nfg, ngo, ctr, ln, fm, fn, naf, ret, vet, cvr, vol, adm }

        // This class already overrides GetPersonnaType, ProcessDefaults and ProcessCert.
        // Per your request: keep existing overrides unchanged.
        public override string GetPersonnaType(X509Certificate2 cert)
        {
            string? _PersonalTypeStr = null;
            if (cert == null)
                return string.Empty;
            if (cert.Extensions == null)
                return string.Empty;

            X509Extension? sanExt = null;
            foreach (X509Extension ext in cert.Extensions)
            {
                if (ext.Oid != null && ext.Oid.FriendlyName == "Subject Alternative Name")
                {
                    sanExt = ext;
                    break;
                }
            }
            if (sanExt == null)
            {
                _logger.LogDebug("DoDSIPRCertProvider:GetPersonnaType: Subject Alternative Name extension not found, using base processing.");
                return base.GetPersonnaType(cert) ?? string.Empty;
            }

            string _san = "";
            if (sanExt != null)
            {
                _san = sanExt.Format(false);
            }
            _PersonalTypeStr = Utility.GetPersonna(_san);

            if (!string.IsNullOrEmpty(_PersonalTypeStr))
            {
                _logger.LogDebug("DoDSIPRCertProvider:GetPersonnaType: Extracted personna type: {Personna}", _PersonalTypeStr);
                try
                {
                    _PersonaType = (personaType)Enum.Parse(typeof(personaType), _PersonalTypeStr.ToLower());
                    _logger.LogDebug("DoDSIPRCertProvider:GetPersonnaType: Parsed personna type enum: {Enum}", _PersonaType);
                    return _PersonaType.ToString();
                }
                catch
                {
                    _logger.LogDebug("DoDSIPRCertProvider:GetPersonnaType: Failed to parse personna type: {Personna}, using base processing.", _PersonalTypeStr);
                    return _PersonalTypeStr;
                }
            }
            _logger.LogDebug("DoDSIPRCertProvider:GetPersonnaType: Personna type not found in SAN, using base processing.");
            return base.GetPersonnaType(cert) ?? string.Empty;
        }

        public override bool IsProvider(X509Certificate2 cert)
        {
            if (cert == null)
            {
                _logger.LogDebug("DoDSIPRCertProcessor.IsProvider: cert is null");
                return false;
            }

            var subject = cert.Subject ?? string.Empty;
            // expected OU value from the override; strip "OU=" prefix if present
            var expectedOu = this.OU ?? string.Empty;
            if (expectedOu.StartsWith("OU=", StringComparison.OrdinalIgnoreCase))
                expectedOu = expectedOu.Substring(3).Trim();

            _logger.LogDebug("DoDSIPRCertProcessor.IsProvider: Subject='{Subject}', ExpectedOU='{ExpectedOU}'", subject, expectedOu);

            try
            {
                // Extract all OU attribute values (handles "OU=Value" or "OU = Value" and multiple OUs)
                var matches = System.Text.RegularExpressions.Regex.Matches(subject, @"OU\s*=\s*([^,]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                foreach (System.Text.RegularExpressions.Match m in matches)
                {
                    var ouVal = m.Groups[1].Value.Trim();
                    _logger.LogDebug("DoDSIPRCertProcessor.IsProvider: Found OU='{OUVal}'", ouVal);
                    if (string.Equals(ouVal, expectedOu, StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("DoDSIPRCertProcessor.IsProvider: Match successful.");
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "DoDSIPRCertProcessor.IsProvider: Exception parsing subject; falling back to base logic.");
            }

            // fallback to base implementation (keeps backward compatibility)
            var baseResult = base.IsProvider(cert);
            _logger.LogDebug("DoDSIPRCertProcessor.IsProvider: base.IsProvider returned {Result}", baseResult);
            return baseResult;
        }
        public override void ProcessDefaults(X509Certificate2 cert)
        {
            base.ProcessDefaults(cert);

            List<PKIAuthInfo> pKIAuthInfos = Utility.GetParseConfig(Config["SmartCard:ConfigPath"]);

            _logger.LogDebug("DoDSIPRCertProvider:ProcessCert: Starting Processing");

            //Get the personna type
            string _PersonnaTypeStr = this.GetPersonnaType(cert);

            //The DoD Id is needed and different than the Identifer
            //it is used to access services and the EDS database
            //it is only different from the identifier bacause nothing 
            //has been appended or prefixed to the value
            string _dodId = GetUPN(cert) ?? string.Empty; // Utility.ProcessQuery("0;,|1;=", cert.Subject);
            if (_dodId.LastIndexOf('@') > 0)
            {
                _dodId = _dodId.Substring(0, _dodId.LastIndexOf('@')).Trim();
            }

            this.NameIdentifier = _dodId;

            _logger.LogDebug("DoDSIPRCertProvider:ProcessDefaults: Identifier: {Id}", _dodId);

            if (IsWindows)
            {
                // Fix: Ensure Config is not null before dereferencing
                if (Config != null)
                {
                    this.UniqueIdentifier = "DOD-" + _dodId.Substring(0, _dodId.LastIndexOf('.')).Trim() + _PersonnaTypeStr;
                }
                else
                {
                    // Handle the case where Config is null, if needed
                    this.UniqueIdentifier = this.UPN;
                }
                _logger.LogDebug("DoDSIPRCertProvider:ProcessDefaults: UniqueIdentifier: {UniqueId}", this.UniqueIdentifier);
            }
            else
            {
                this.UniqueIdentifier = _dodId.ToUpper();
                _logger.LogDebug("DoDSIPRCertProvider:ProcessDefaults: UniqueIdentifier (Non-Windows): {UniqueId}", this.UniqueIdentifier);
            }

            if (_dodId.LastIndexOf('.') > 0)
                this.EDIPI = _dodId.Substring(0, _dodId.LastIndexOf('.')).Trim();
            else
                this.EDIPI = _dodId.Trim();
            _logger.LogDebug("DoDSIPRCertProvider:ProcessDefaults: EDIPI: {EDIPI}", this.EDIPI);
        }

        // methods copied from former base that were not overridden in this class
        public override string GetSAN(X509Certificate2 cert)
        {
            X509Extension? sanExt = cert.Extensions["Subject Alternative Name"];
            string _san = "";

            if (sanExt != null)
            {
                _san = sanExt.Format(false);
            }
            _logger.LogDebug("CertProvider:GetSAN: SAN: {SAN}", _san);
            return _san;
        }

        public override string GetEmail(X509Certificate2 cert)
        {
            string _san = GetSAN(cert);
            string? upn = null;
            string? email = null;

            if (_san != null)
            {
                string[] finditems = _san.Split(',');

                _logger.LogDebug("CertProvider:GetEmail: SAN Items Found: {Count}", finditems.Length);

                foreach (string item in finditems)
                {
                    if (item != null)
                    {
                        var processedQuery = Utility.ProcessQuery("0;=", item.ToLower());
                        if (!string.IsNullOrEmpty(processedQuery) && processedQuery.IndexOf("principal name") > 0)
                        {
                            upn = Utility.ProcessQuery("1;=", item);
                        }
                        if (!string.IsNullOrEmpty(processedQuery) && processedQuery.IndexOf("rfc822 name") > 0)
                        {
                            email = Utility.ProcessQuery("1;=", item);
                        }
                    }
                }
                if (string.IsNullOrWhiteSpace(email) && !string.IsNullOrWhiteSpace(upn))
                {
                    email = upn;
                }
            }

            _logger.LogDebug("CertProvider:GetEmail: Email: {Email}", email);

            return email ?? string.Empty;
        }

        public override string GetUPN(X509Certificate2 cert)
        {
            string _san = GetSAN(cert);
            string? upn = null;

            if (_san != null)
            {
                _logger.LogDebug("CertProvider:GetUPN: SAN: {SAN}", _san);

                string[] finditems = _san.Split(',');
                string? email = null;

                foreach (string item in finditems)
                {
                    if (item != null)
                    {
                        var processedQuery = Utility.ProcessQuery("0;=", item.ToLower());
                        if (!string.IsNullOrEmpty(processedQuery) && processedQuery.IndexOf("principal name") > 0)
                        {
                            upn = Utility.ProcessQuery("1;=", item);
                        }
                        if (!string.IsNullOrEmpty(processedQuery) && processedQuery.IndexOf("rfc822 name") > 0)
                        {
                            email = Utility.ProcessQuery("1;=", item);
                        }
                    }
                }
                if (string.IsNullOrWhiteSpace(upn) && !string.IsNullOrWhiteSpace(email))
                {
                    upn = email;
                }
            }

            _logger.LogDebug("CertProvider:GetUPN: UPN: {UPN}", upn);
            return upn ?? string.Empty;
        }

        public override void ProcessCert(X509Certificate2 cert, ref ClaimsIdentity outputIdentity)
        {
            base.ProcessCert(cert, ref outputIdentity);
            if (outputIdentity == null)
                outputIdentity = new ClaimsIdentity();

            outputIdentity.AddClaim(new Claim("http://" + this.ClaimOrgnization + "/edipi", this.EDIPI ?? ""));
            _logger.LogDebug("DoDSIPRCertProvider:ProcessCert: Added EDIPI claim: {EDIPI}", (this.EDIPI ?? ""));

            if (SAN != null)
            {
                _logger.LogDebug("DefaultCertProcessor.ProcessCert: Found SAN extension.");
                outputIdentity.AddClaim(new Claim("http://schemas.microsoft.com/2012/12/certificatecontext/extension/san", SAN));
            }
        }
    }
}
