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
    public class Args_Get_NetLocalGroupMember
    {
        public string[] ComputerName { get; set; } = { Environment.GetEnvironmentVariable("COMPUTERNAME") };
        public string[] HostName { get { return ComputerName; } set { ComputerName = value; } }
        public string[] dnshostname { get { return ComputerName; } set { ComputerName = value; } }
        public string[] name { get { return ComputerName; } set { ComputerName = value; } }

        public string GroupName { get; set; } = "Administrators";

        public MethodType Method { get; set; } = MethodType.API;
        public MethodType CollectionMethod { get { return Method; } set { Method = value; } }

        public NetworkCredential Credential { get; set; }
    }
}
