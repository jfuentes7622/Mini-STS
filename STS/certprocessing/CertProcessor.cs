using FSCA.Support;
//using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace FSCA.CertProcessing
{
    internal abstract class CertProcessor : ILoginDefaults
    {
        protected readonly ILogger _logger;

        public string DisplayName { get; set; } = string.Empty;
        public string UPN { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string ClaimName { get; set; } = string.Empty;
        public string EmployeeId { get; set; } = string.Empty;
        public string UniqueIdentifier { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string MiddleName { get; set; } = string.Empty;
        public string Organization { get; set; } = string.Empty;
        public string EDIPI { get; set; } = string.Empty;
        public string NameIdentifier { get; set; } = string.Empty;
        public string SAN { get; set; } = string.Empty;
        public bool IsWindows { get; set; }
        public PKIAuthInfo? FormatInfo { get; set; } = null;
        public IConfiguration Config { get; set; }

        // make convenience ctor protected so consumers cannot instantiate without a logger
        protected CertProcessor(IConfiguration config) : this(config, NullLogger.Instance) { }

        // New constructor accepting an ILogger
        public CertProcessor(IConfiguration config, ILogger logger)
        {
            this.Config = config;
            _logger = logger ?? NullLogger.Instance;
            // All properties/fields are initialized at declaration above.
        }

        //This is the main method used to process the certificate
        public abstract void ProcessCert(X509Certificate2 cert, ref ClaimsIdentity outputIdentity);

        // Make the following methods abstract so derived classes own implementations
        public abstract bool IsProvider(X509Certificate2 cert);
        public abstract string GetPersonnaType(X509Certificate2 cert);
        public abstract string GetSAN(X509Certificate2 cert);
        public abstract string GetEmail(X509Certificate2 cert);
        public abstract string GetUPN(X509Certificate2 cert);
        public abstract void ProcessDefaults(X509Certificate2 cert);

        public abstract string OU { get; }


        public virtual string Identifier { get; set; } = string.Empty;


        public virtual string ClaimOrgnization { get; set; } = string.Empty;

        public virtual string PerferedName { get; set; } = string.Empty;


        public virtual string CertificateSerial { get; set; } = string.Empty;

        // Change the OrgAbv property to have a public setter so it can be set from DefaultCertProcessor
        public string? OrgAbv { get; set; }

    }
}
