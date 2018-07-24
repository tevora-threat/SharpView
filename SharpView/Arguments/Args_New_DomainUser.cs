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
    public class Args_New_DomainUser
    {
        public string SamAccountName { get; set; }

        public System.Security.SecureString AccountPassword { get; set; }
        public System.Security.SecureString Password { get { return AccountPassword; } set { AccountPassword = value; } }

        public string Name { get; set; }

        public string DisplayName { get; set; }

        public string Description { get; set; }

        public string Domain { get; set; }

        public NetworkCredential Credential { get; set; }
    }
}
