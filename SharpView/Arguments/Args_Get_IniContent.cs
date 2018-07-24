using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using SharpView.Utils;

namespace SharpView.Arguments
{
    public class Args_Get_IniContent
    {
        public string[] Path { get; set; }
        public string[] FullName { get { return Path; } set { Path = value; } }
        public string[] Name { get { return Path; } set { Path = value; } }

        public NetworkCredential Credential { get; set; }
    }
}
