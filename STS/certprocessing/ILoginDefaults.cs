using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace FSCA.CertProcessing
{
    internal class ILoginDefaults
    {
        string? DisplayName { get; set; }

        string? UPN { get; set; }

        string? Email { get; set; }

        string? ClaimName { get; set; }

        string? EmployeeId { get; set; }

        string? UniqueIdentifier { get; set; }

        bool IsInternal { get; set; }

        string? FirstName { get; set; }

        string? LastName { get; set; }

        string? MiddleName { get; set; }

        string? Organization { get; set; }

        string? EDIPI { get; set; }

        string? NameIdentifier { get; set; }

        bool IsWindows { get; set; }
    }

    [DataContract]
    public class PKIAuthInfo
    {
        [DataMember] public string OU { get; set; } = string.Empty;
        [DataMember] public string FirstName { get; set; } = string.Empty;
        [DataMember] public string LastName { get; set; } = string.Empty;
        [DataMember] public string MiddleName { get; set; } = string.Empty;
        [DataMember] public bool IsSubjectIdentifier { get; set; }
        [DataMember] public string SubjectIdentifier { get; set; } = string.Empty;
        [DataMember] public string Organization { get; set; } = string.Empty;
        [DataMember] public string Personna { get; set; } = string.Empty;
        [DataMember] public string OrganizationShort { get; set; } = string.Empty;
        [DataMember] public string RCFromSAN { get; set; } = string.Empty;
        [DataMember] public string SubjectReplaceChar { get; set; } = string.Empty;
        [DataMember] public string Sample { get; set; } = string.Empty;
        [DataMember] public string SANSample { get; set; } = string.Empty;
    }
}
