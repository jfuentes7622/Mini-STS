using FSCA.Support;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace FSCA.CertProcessing
{
    internal class DefaultCertProcessor : CertProcessor
    {
        // Require ILogger<T> so DI will inject a real logger
        public DefaultCertProcessor(IConfiguration config, ILogger<DefaultCertProcessor> logger) : base(config, logger) { }

        //This is the default provider so it doesn't need to match 1 certificate directly
        //its created to process any certificate that doesn't have a matching provider
        public override bool IsProvider(X509Certificate2 cert)
        {
            return false;
        }

        public override string OU
        {
            get { return ""; }
        }
        public string Network => "BOTH";

        // Copy of previous base.GetSAN implementation
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

        // Copy of previous base.GetEmail implementation (do not call base)
        public override string GetEmail(X509Certificate2 cert)
        {
            string _san = GetSAN(cert);
            string? upn = null;
            string? email = null;

            if (_san != null)
            {
                //There are two possible values to pull
                //1) Principal Name (most commonly used for UPN)
                //2) RFC822 Name (most commonly used for email)

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

        // Copy of previous base.GetUPN implementation
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

        // DefaultCertProcessor had its own GetEmail and ProcessCert; copy base.ProcessDefaults into this class
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

                CertificateSerial = cert.SerialNumber;
                //some subjects have spaces "Jose c Fuentes, while others have periods "Jose.C.Fuentes"
                //Easier to simply convert all spaces to periods.
                string _subject = cert.Subject.Substring(3, cert.Subject.IndexOf("OU=") - 3).Trim().Replace(' ', '.').Replace('"', ' ').ToLower();

                _logger.LogDebug("CertProvider:ProcessDefaults: Process name items out of: {Subject}", _subject);

                //Pull first name from Subject, note using culture to convert "JOSE" to "Jose"
                // Fix for CS8604: Ensure argument to ToTitleCase is not null
                this.FirstName = CultureInfo.InvariantCulture.TextInfo.ToTitleCase(
                    Utility.ProcessQuery(FormatInfo.FirstName, _subject) ?? string.Empty
                );
                _logger.LogDebug("CertProvider:ProcessDefaults: First Name: {FirstName}", this.FirstName);

                this.LastName = CultureInfo.InvariantCulture.TextInfo.ToTitleCase(
                    Utility.ProcessQuery(FormatInfo.LastName, _subject) ?? string.Empty
                );
                _logger.LogDebug("CertProvider:ProcessDefaults: Last Name: {LastName}", this.LastName);

                // Also fix for MiddleName assignment
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

                //Covers Jr, Sr, etc.
                if ((_subject.Count(c => c == '.') > 3))
                {
                    //set suffix
                    this.LastName += " " + Utility.ProcessQuery(FormatInfo.SubjectIdentifier, cert.Subject.Replace(' ', '.'));
                    _logger.LogDebug("CertProvider:ProcessDefaults: Suffix added to Last Name: {LastName}", this.LastName);
                }

                //This pulls the personna type based on the Cert, 
                //different providers might determine the personna type differently
                //hence why the whole cert is passed
                string _personnaType = GetPersonnaType(cert) ?? string.Empty;

                _logger.LogDebug("CertProvider:ProcessDefaults: personaType: {Personna}", _personnaType);

                //Here the full display name is setup
                PerferedName = LastName + ", " + FirstName + " " + MiddleName + ((_personnaType == null) ? "" : " - " + _personnaType) + " - " + FormatInfo.OrganizationShort;

                _logger.LogDebug("CertProvider:ProcessDefaults: Perfered Name: {PerferedName}", PerferedName);

                //if SetPerferedName == true then we populate it here in the base
                //if (this.SetPerferedName())
                //{ 
                this.DisplayName = PerferedName;
                // }

                //if (this.SetNameIdentifier())
                //{ 
                this.NameIdentifier = CertificateSerial;
                // }

                _logger.LogDebug("CertProvider:ProcessDefaults: Setup default Roles");


                this.OrgAbv = FormatInfo.OrganizationShort;

                //Get Subject Alternative Name section
                X509Extension? sanExt = cert.Extensions["Subject Alternative Name"];
                string _san = "";

                if (sanExt != null)
                {
                    _san = sanExt.Format(false);
                    this.SAN = _san;

                    this.Email = GetEmail(cert);
                    this.ClaimName = GetEmail(cert);

                    //if subject does not have the Identifier, then use the RC value in the SAN
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

                //Just like SetPerferedName, if a provider wants or has more data for to set the organization
                //then they can override it by passing false in the SetOrganization override, then the base
                //will not set the organization
                this.Organization = FormatInfo.Organization;
                _logger.LogDebug("CertProvider:ProcessDefaults: Organization: {Org}", FormatInfo.Organization);
            }
            else
            {
                _logger.LogDebug("CertProvider:ProcessDefaults: No default info found for cert.");
            }
        }

        public override void ProcessCert(X509Certificate2 cert, ref ClaimsIdentity outputIdentity)
        {
            if (outputIdentity == null)
                outputIdentity = new ClaimsIdentity();

            outputIdentity.AddClaim(new Claim("http://schemas.microsoft.com/2012/12/certificatecontext/field/subject", cert.Subject));
            outputIdentity.AddClaim(new Claim("http://schemas.microsoft.com/2012/12/certificatecontext/field/issuer", cert.Issuer));
            outputIdentity.AddClaim(new Claim(ClaimTypes.Thumbprint, cert.Thumbprint));
            outputIdentity.AddClaim(new Claim(ClaimTypes.SerialNumber, cert.SerialNumber));

            //Get Subject Alternative Name section
            X509Extension? sanExt = cert.Extensions["Subject Alternative Name"];
            string _san = "";
            if (sanExt != null)
            {
                _logger.LogDebug("DefaultCertProcessor.ProcessCert: Found SAN extension.");
                outputIdentity.AddClaim(new Claim("http://schemas.microsoft.com/2012/12/certificatecontext/extension/san", _san));
            }

            outputIdentity.AddClaim(new Claim("http://" + this.ClaimOrgnization + "/displayname", DisplayName ?? string.Empty));
            outputIdentity.AddClaim(new Claim("http://" + this.ClaimOrgnization + "/uniqueuserid", this.UniqueIdentifier ?? cert.SerialNumber));
            
            // Ensure UPN is not null
            if (!string.IsNullOrEmpty(UPN))
            {
                _logger.LogDebug("DefaultCertProcessor.ProcessCert: Adding UPN claim: {UPN}", UPN);
                outputIdentity.AddClaim(new Claim(ClaimTypes.Upn, UPN));
            }

            outputIdentity.AddClaim(new Claim(ClaimTypes.GivenName, FirstName ?? string.Empty));
            outputIdentity.AddClaim(new Claim(ClaimTypes.Surname, LastName ?? string.Empty));
            outputIdentity.AddClaim(new Claim(ClaimTypes.Email, Email ?? string.Empty));
            outputIdentity.AddClaim(new Claim(ClaimTypes.Role, GetPersonnaType(cert) ?? string.Empty));


            outputIdentity.AddClaim(new Claim(ClaimTypes.Role, IsWindows ? "InternalUser" : "NonInternalUser"));
            _logger.LogDebug("DefaultCertProcessor.ProcessCert: Completed processing certificate and adding claims.");
        }

        public override string GetPersonnaType(X509Certificate2 cert)
        {
            string _personnaType = Utility.GetPersonna(GetUPN(cert));
            string _subject = cert.Subject.Trim().Replace(' ', '.').Replace('"', ' ').ToLower();
            //Here the persona is set, either it came out of the subject or processed above
            string _personna = (FormatInfo?.Personna == null) ? _personnaType : Utility.ProcessQuery(FormatInfo.Personna, _subject.ToUpper());

            _personna = (string.IsNullOrEmpty(_personna)) ? _personnaType : _personna;

            _logger.LogInformation("DefaultCertProvider:ProcessDefaults: Personna: {Personna}", _personna);
            return _personna;
        }
    }
}
