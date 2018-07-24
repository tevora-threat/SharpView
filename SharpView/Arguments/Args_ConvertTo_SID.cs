using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Arguments
{
    public class Args_ConvertTo_SID
    {
        public string[] ObjectName { get; set; }
        public string[] Name { get { return ObjectName; } set { ObjectName = value; } }
        public string[] Identity { get { return ObjectName; } set { ObjectName = value; } }

        public string Domain { get; set; }

        public string Server { get; set; }
        public string DomainController { get { return Server; } set { Server = value; } }

        public NetworkCredential Credential { get; set; }
    }
}
