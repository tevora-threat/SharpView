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
    public class Args_Get_WMIRegProxy
    {
        public string[] ComputerName { get; set; } = new[] { Environment.GetEnvironmentVariable("COMPUTERNAME") };
        public string[] HostName { get { return ComputerName; } set { ComputerName = value; } }
        public string[] dnshostname { get { return ComputerName; } set { ComputerName = value; } }
        public string[] name { get { return ComputerName; } set { ComputerName = value; } }

        public NetworkCredential Credential { get; set; }
    }
}
