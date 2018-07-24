using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class SPNTicket
    {
        public string TicketByteHexStream { get; set; }

        public string Hash { get; set; }

        public string SamAccountName { get; set; }

        public string DistinguishedName { get; set; }

        public string ServicePrincipalName { get; set; }
    }
}
