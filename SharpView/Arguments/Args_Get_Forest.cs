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
    public class Args_Get_Forest
    {
        public string Forest { get; set; }
        public string Name { get { return Forest; } set { Forest = value; } }

        public NetworkCredential Credential { get; set; }
    }
}
