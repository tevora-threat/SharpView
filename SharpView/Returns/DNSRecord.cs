using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class DNSRecord
    {
        public DnsRecordType? RecordType { get; set; }

        public uint? UpdatedAtSerial { get; set; }

        public uint? TTL { get; set; }

        public uint? Age { get; set; }

        public object TimeStamp { get; set; } // DateTime or string ("[static]")

        public string Data { get; set; }

        public string ZoneName { get; set; }

        public string name { get; set; }

        public string distinguishedname { get; set; }

        public object dnsrecord { get; set; }

        public DateTime? whencreated { get; set; }

        public DateTime? whenchanged { get; set; }
    }
}
