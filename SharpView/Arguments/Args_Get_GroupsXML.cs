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
    public class Args_Get_GroupsXML
    {
        public string GroupsXMLPath { get; set; }
        public string Path { get { return GroupsXMLPath; } set { GroupsXMLPath = value; } }

        public NetworkCredential Credential { get; set; }
    }
}
