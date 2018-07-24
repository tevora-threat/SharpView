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
    public class Args_Get_PrincipalContext
    {
        public string Identity { get; set; }
        public string GroupName { get { return Identity; } set { Identity = value; } }
        public string GroupIdentity { get { return Identity; } set { Identity = value; } }

        public string Domain { get; set; }

        public NetworkCredential Credential { get; set; }
    }
}
