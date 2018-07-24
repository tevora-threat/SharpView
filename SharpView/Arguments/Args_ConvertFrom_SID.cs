using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Arguments
{
    public class Args_ConvertFrom_SID
    {
        public string[] ObjectSID { get; set; }
        public string[] SID { get { return ObjectSID; } set { ObjectSID = value; } }

        public string Domain { get; set; }

        public string Server { get; set; }
        public string DomainController { get { return Server; } set { Server = value; } }

        public NetworkCredential Credential { get; set; }
    }
}
