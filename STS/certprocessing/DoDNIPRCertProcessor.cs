using FSCA.Support;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Runtime.InteropServices;
using System.Globalization;

namespace FSCA.CertProcessing
{
    internal class DoDNIPRCertProcessor : DefaultCertProcessor
    {
        // Require ILogger<T> so DI will inject a real logger
        public DoDNIPRCertProcessor(IConfiguration config, ILogger<DoDNIPRCertProcessor> logger) : base(config, logger) { }

        public override string OU => "OU=DoD";

        // Copy of base.GetPersonnaType
        public override string GetPersonnaType(X509Certificate2 cert)
        {
            string _personnaType = Utility.GetPersonna(GetUPN(cert));
            string _subject = cert.Subject.Trim().Replace(' ', '.').Replace('"', ' ').ToLower();
            string _personna = (FormatInfo == null || FormatInfo.Personna == null)
                ? _personnaType
                : Utility.ProcessQuery(FormatInfo.Personna, _subject.ToUpper());

            _personna = (string.IsNullOrEmpty(_personna)) ? _personnaType : _personna;

            _logger.LogDebug("CertProvider:GetPersonnaType: Personna: {Personna}", _personna);
            return _personna;
        }

        // Copy of base.GetSAN
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

        public override void ProcessCert(X509Certificate2 cert, ref ClaimsIdentity outputIdentity)
        {
            base.ProcessCert(cert, ref outputIdentity);
            if (outputIdentity == null)
                outputIdentity = new ClaimsIdentity();

            string nationality = ProcessNationality(cert);
            if (nationality != null)
            {
                _logger.LogDebug("DodNIPRCertProcessor.ProcessCert: Extracted nationality: {Nationality}", nationality);
                outputIdentity.AddClaim(new Claim(ClaimTypes.Role, nationality));
            }

            
        }

        private string ProcessNationality(X509Certificate2 cert)
        {
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid == null) continue;
                if (ext.Oid.Value == "2.5.29.9")
                {
                    if (ext.Format(true).EndsWith("13 02 55 53"))
                    {
                        return "US";
                    }
                    else
                    {
                        string cc = "";
                        string[] dStr = ext.Format(true).Split(' ');
                        int val1 = Convert.ToInt32(dStr[dStr.Length - 2], 16);
                        int val2 = Convert.ToInt32(dStr[dStr.Length - 1], 16);
                        cc = Char.ConvertFromUtf32(val1);
                        cc += char.ConvertFromUtf32(val2);
                        return cc;
                    }
                }
            }
            return "00";
        }

        public override string GetEmail(X509Certificate2 cert)
        {
            string _san = GetSAN(cert);

            if (_san != null)
            {
                foreach (string part in _san.Split(','))
                {
                    if (part.Contains("RFC822"))
                        return part.Split('=')[1];
                }
            }

            _logger.LogDebug("DodNIPRCertProcessor.GetEmail: No email found in SAN, falling back to default behavior.");
            // fallback: use base-style logic (here GetUPN)
            return GetUPN(cert) ?? string.Empty;
        }

        public override bool IsProvider(X509Certificate2 cert)
        {
            if (cert == null)
            {
                _logger.LogDebug("DoDNIPRCertProcessor.IsProvider: cert is null");
                return false;
            }

            var subject = cert.Subject ?? string.Empty;
            // expected OU value from the override; strip "OU=" prefix if present
            var expectedOu = this.OU ?? string.Empty;
            if (expectedOu.StartsWith("OU=", StringComparison.OrdinalIgnoreCase))
                expectedOu = expectedOu.Substring(3).Trim();

            _logger.LogDebug("DoDNIPRCertProcessor.IsProvider: Subject='{Subject}', ExpectedOU='{ExpectedOU}'", subject, expectedOu);

            try
            {
                // Extract all OU attribute values (handles "OU=Value" or "OU = Value" and multiple OUs)
                var matches = System.Text.RegularExpressions.Regex.Matches(subject, @"OU\s*=\s*([^,]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                foreach (System.Text.RegularExpressions.Match m in matches)
                {
                    var ouVal = m.Groups[1].Value.Trim();
                    _logger.LogDebug("DoDNIPRCertProcessor.IsProvider: Found OU='{OUVal}'", ouVal);
                    if (string.Equals(ouVal, expectedOu, StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("DoDNIPRCertProcessor.IsProvider: Match successful.");
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "DoDNIPRCertProcessor.IsProvider: Exception parsing subject; falling back to default logic.");
            }

            // fallback to DefaultCertProcessor implementation (which returns false)
            var baseResult = base.IsProvider(cert);
            _logger.LogDebug("DoDNIPRCertProcessor.IsProvider: base.IsProvider returned {Result}", baseResult);
            return baseResult;
        }

        // Copy of base.ProcessDefaults
        public override void ProcessDefaults(X509Certificate2 cert)
        {
            _logger.LogDebug("CertProvider:ProcessDefaults: Start Processing");

            List<PKIAuthInfo> pKIAuthInfos = Utility.GetParseConfig(Config["SmartCard:ConfigPath"]);

            if (pKIAuthInfos != null)
            {
                _logger.LogDebug("CertProvider:ProcessDefaults: Get defaults based on cert");
                if (string.IsNullOrEmpty(OU))
                {
                    //OU not poulated, find object that matches Cert
                    foreach (PKIAuthInfo infoitem in pKIAuthInfos)
                    {
                        if (cert.Subject.Contains(infoitem.OU))
                        {
                            this.FormatInfo = infoitem;
                            _logger.LogDebug("CertProvider:ProcessDefaults: default found for cert for OU: {OU}", FormatInfo.OU);
                            break;
                        }
                    }
                }
                else //get object based on OU (when buildin a dedicated provider but still setting the defaults
                {
                    this.FormatInfo = pKIAuthInfos.Find(x => x.OU == this.OU);
                }
            }

            this.UPN = GetUPN(cert);
            this.IsWindows = false;

            // CA1416 fix: Only call Utility.IsWindowsUser on Windows
            if (!string.IsNullOrEmpty(UPN) && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                this.IsWindows = Utility.IsWindowsUser(UPN, _logger);
            }

            if (FormatInfo != null) //info is populated then do the following:
            {

                // Ensure CertificateSerial is set locally
                // Use existing backing field _CertificateSerial from base via property CertificateSerial - but we set the backing field using reflection to keep same behavior
                // Simpler: set local certificate serial via the property on the base (CertificateSerial is virtual and backed in base)
                // However CertificateSerial's backing field is not directly accessible; use the same pattern as base used (assign to a local field if needed)
                // For simplicity, set UniqueIdentifier and CertificateSerial via available properties where possible.
                // We'll set via the same backing approach used in DefaultCertProcessor: set cert serial into local backing by calling ProcessCert expectations.
                // Here assign visibile property via reflection is unnecessary; use UniqueIdentifier/NameIdentifier as in other processors.

                // set certificate serial
                // The base had _CertificateSerial private; we can use NameIdentifier / UniqueIdentifier instead for downstream logic
                // For consistency set UniqueIdentifier to UPN as fallback
                // (Most code reads CertificateSerial or NameIdentifier; this will be acceptable)

                // Some of the original base behavior relies on private backing fields; replicate the most important assignments:
                // set DisplayName, FirstName/LastName etc.

                //some subjects have spaces "Jose c Fuentes, while others have periods "Jose.C.Fuentes"
                //Easier to simply convert all spaces to periods.
                string _subject = cert.Subject.Substring(3, cert.Subject.IndexOf("OU=") - 3).Trim().Replace(' ', '.').Replace('"', ' ').ToLower();

                _logger.LogDebug("CertProvider:ProcessDefaults: Process name items out of: {Subject}", _subject);

                this.FirstName = CultureInfo.InvariantCulture.TextInfo.ToTitleCase(
                    Utility.ProcessQuery(FormatInfo.FirstName, _subject) ?? string.Empty
                );
                _logger.LogDebug("CertProvider:ProcessDefaults: First Name: {FirstName}", this.FirstName);

                this.LastName = CultureInfo.InvariantCulture.TextInfo.ToTitleCase(
                    Utility.ProcessQuery(FormatInfo.LastName, _subject) ?? string.Empty
                );
                _logger.LogDebug("CertProvider:ProcessDefaults: Last Name: {LastName}", this.LastName);

                if ((_subject.Count(c => c == '.') > 2 && FormatInfo.IsSubjectIdentifier) || (_subject.Count(c => c == '.') == 2 && !FormatInfo.IsSubjectIdentifier))
                {
                    this.MiddleName = CultureInfo.InvariantCulture.TextInfo.ToTitleCase(
                        Utility.ProcessQuery(FormatInfo.MiddleName, _subject) ?? string.Empty
                    );
                    _logger.LogDebug("CertProvider:ProcessDefaults: Middle Name: {MiddleName}", this.MiddleName);
                }
                else
                {
                    this.MiddleName = "";
                }

                if ((_subject.Count(c => c == '.') > 3))
                {
                    this.LastName += " " + Utility.ProcessQuery(FormatInfo.SubjectIdentifier, cert.Subject.Replace(' ', '.'));
                    _logger.LogDebug("CertProvider:ProcessDefaults: Suffix added to Last Name: {LastName}", this.LastName);
                }

                string _personnaType = GetPersonnaType(cert) ?? string.Empty;

                _logger.LogDebug("CertProvider:ProcessDefaults: personaType: {Personna}", _personnaType);

                PerferedName = LastName + ", " + FirstName + " " + MiddleName + ((_personnaType == null) ? "" : " - " + _personnaType) + " - " + FormatInfo.OrganizationShort;

                _logger.LogDebug("CertProvider:ProcessDefaults: Perfered Name: {PerferedName}", PerferedName);

                this.DisplayName = PerferedName;

                this.NameIdentifier = CertificateSerial;

                _logger.LogDebug("CertProvider:ProcessDefaults: Setup default Roles");

                this.OrgAbv = FormatInfo.OrganizationShort;

                X509Extension? sanExt = cert.Extensions["Subject Alternative Name"];
                string _san = "";

                if (sanExt != null)
                {
                    _san = sanExt.Format(false);

                    this.Email = GetEmail(cert);
                    this.ClaimName = GetEmail(cert);

                    Identifier = Utility.ProcessQuery(FormatInfo.RCFromSAN, _san);
                    this.EmployeeId = Identifier;

                    _logger.LogDebug("CertProvider:ProcessDefaults: Email: {Email}", this.Email);
                }

                try
                {
                    if (FormatInfo.IsSubjectIdentifier) //here if value is in subject as identifier then overwrite _id
                    {
                        _logger.LogDebug("CertProvider:ProcessDefaults: Processing Subject Identifier");
                        if ((_subject.Count(c => c == '.') > 3))
                        {
                            string _dodId = Utility.ProcessQuery("0;,|1;=", cert.Subject);
                            if (!string.IsNullOrEmpty(_dodId))
                            {
                                _dodId = _dodId.Remove(0, _dodId.LastIndexOf('.') + 1).Trim();
                                Identifier = _dodId;
                                this.EDIPI = _dodId.Remove(0, _dodId.LastIndexOf('@') + 1).Trim();
                            }
                            _logger.LogDebug("CertProvider:ProcessDefaults: DOD ID from Subject Identifier: {Id}", Identifier);
                        }
                        else
                        {
                            Identifier = Utility.ProcessQuery(FormatInfo.SubjectIdentifier, cert.Subject.Replace(' ', '.'));
                            _logger.LogDebug("CertProvider:ProcessDefaults: ID from Subject Identifier: {Id}", Identifier);
                            this.EDIPI = Identifier;
                        }

                        if (string.IsNullOrWhiteSpace(Identifier))
                        {
                            string _dodId = Utility.ProcessQuery("0;,|1;=", cert.Subject);
                            if (!string.IsNullOrEmpty(_dodId))
                            {
                                _dodId = _dodId.Remove(0, _dodId.LastIndexOf('.') + 1).Trim();
                                Identifier = _dodId;
                                this.EDIPI = _dodId.Remove(0, _dodId.LastIndexOf('@') + 1).Trim();
                                _logger.LogDebug("CertProvider:ProcessDefaults: DOD ID from Subject Identifier (fallback): {Id}", Identifier);
                            }
                        }

                        if (!string.IsNullOrWhiteSpace(Identifier))
                        {
                            Identifier = FormatInfo.OrganizationShort + "-" + Identifier.Remove(0, Identifier.LastIndexOf('.') + 1).Trim();
                            if (!string.IsNullOrEmpty(_personnaType))
                            {
                                Identifier = Identifier + "-" + _personnaType;
                            }
                            _logger.LogDebug("CertProvider:ProcessDefaults: Final Identifier with Org and Personna: {Id}", Identifier);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "CertProvider:ProcessDefaults: Exception while processing subject identifier.");
                }

                _logger.LogDebug("CertProvider:ProcessDefaults: Identifier: {Id}", Identifier);

                this.UniqueIdentifier = this.UPN;

                this.Organization = FormatInfo.Organization;
                _logger.LogDebug("CertProvider:ProcessDefaults: Organization: {Org}", FormatInfo.Organization);
            }
            else
            {
                _logger.LogDebug("CertProvider:ProcessDefaults: No default info found for cert.");
            }
        }

        public override string GetUPN(X509Certificate2 cert)
        {
            if (cert == null)
                return string.Empty;
            if (cert.Extensions == null)
                return string.Empty;

            // Initialize sanExt to null to avoid CS0165
            X509Extension? sanExt = null;
            foreach (X509Extension ext in cert.Extensions)
            {
                if (ext.Oid != null && ext.Oid.FriendlyName == "Subject Alternative Name")
                {
                    sanExt = ext;
                    break;
                }
            }

            string _san = "";

            if (sanExt != null)
            {
                _san = sanExt.Format(false);
                if (_san != null)
                {
                    if (_san.Contains("Principal"))
                    {
                        foreach (string part in _san.Split(','))
                        {
                            if (part.Contains("Principal"))
                            {
                                string upn = part.Split('=')[1];
                                _logger.LogDebug("DodNIPRCertProcessor.GetUPN: Extracted UPN from SAN: {UPN}", upn);
                                return upn;
                            }
                        }
                    }
                }
            }

            _logger.LogDebug("DodNIPRCertProcessor.GetUPN: No UPN found in SAN, falling back to base implementation.");
            return base.GetUPN(cert) ?? string.Empty;
        }
    }
}
