

using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class GPOComputerLocalGroupMember
    {
        public IEnumerable<string> ComputerName { get; set; }

        public string ObjectName { get; set; }

        public string ObjectDN { get; set; }

        public string[] ObjectSID { get; set; }

        public bool IsGroup { get; set; }

        public string GPODisplayName { get; set; }

        public string GPOGuid { get; set; }

        public string GPOPath { get; set; }

        public string GPOType { get; set; }
    }
}
