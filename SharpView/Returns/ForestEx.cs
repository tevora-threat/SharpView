using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class ForestEx
    {
        public System.DirectoryServices.ActiveDirectory.Forest Forest { get; set; }
        public string RootDomainSid { get; set; }
    }
}
