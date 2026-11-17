using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FSCA.Support
{
    public class SmartCardConfig
    {
        //public enum TypeIdentifier
        //{
        //    None = 1,
        //    DomainUser = 2,
        //    UPN = 3,
        //    SAM = 4,
        //}
        //public TypeIdentifier GetTypeIdentifier()
        //{
        //    return (TypeIdentifier)this.UseTypeIdentifier;
        //}
        public bool Debug { get; set; } = false;
        public enum envType { SIPR, NIPR, BOTH };
        public envType Environment { get; set; } = envType.NIPR;
        //public int UseTypeIdentifier = 3;
        public string ADFSUrl { get; set; } = string.Empty;
        //public string AppInsightsConnectionString { get; set; } = "";
        public string ApplicationName { get; set; } = "SmartCard-Auth";

        public string DefaultConfigpath { get; set; } = "";

    }

}
