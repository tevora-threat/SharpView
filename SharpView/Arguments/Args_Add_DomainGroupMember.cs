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
    public class Args_Add_DomainGroupMember
    {
        public string Identity { get; set; }
        public string GroupName { get { return Identity; } set { Identity = value; } }
        public string GroupIdentity { get { return Identity; } set { Identity = value; } }

        public string[] Members { get; set; }
        public string[] MemberIdentity { get { return Members; } set { Members = value; } }
        public string[] Member { get { return Members; } set { Members = value; } }
        public string[] DistinguishedName { get { return Members; } set { Members = value; } }

        public string Domain { get; set; }

        public NetworkCredential Credential { get; set; }
    }
}
