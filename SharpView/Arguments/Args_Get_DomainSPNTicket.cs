using SharpView.Enums;
using SharpView.Returns;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Arguments
{
    public class Args_Get_DomainSPNTicket
    {
        public string[] SPN { get; set; }
        public string[] Name { get { return SPN; } set { SPN = value; } }
        public string[] ServicePrincipalName { get { return SPN; } set { SPN = value; } }

        public LDAPProperty User { get; set; }

        public SPNTicketFormat OutputFormat { get; set; }

        public NetworkCredential Credential { get; set; }
    }
}
