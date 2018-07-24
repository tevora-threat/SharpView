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
    public class Args_Get_ForestGlobalCatalog
    {
        public string Forest { get; set; }

        public NetworkCredential Credential { get; set; }
    }
}
