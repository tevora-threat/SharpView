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
    public class Args_Get_PathAcl
    {
        public string[] Path { get; set; }
        public string[] FullName { get { return Path; } set { Path = value; } }

        public NetworkCredential Credential { get; set; }
    }
}
