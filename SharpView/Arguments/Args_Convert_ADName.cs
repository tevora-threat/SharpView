using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Arguments
{
    public class Args_Convert_ADName
    {
        public string[] Identity { get; set; }
        public string[] Name { get { return Identity; } set { Identity = value; } }
        public string[] ObjectName { get { return Identity; } set { Identity = value; } }

        public ADSNameType? OutputType { get; set; }

        public string Domain { get; set; }

        public string Server { get; set; }
        public string DomainController { get { return Server; } set { Server = value; } }

        public NetworkCredential Credential { get; set; }
    }
}
