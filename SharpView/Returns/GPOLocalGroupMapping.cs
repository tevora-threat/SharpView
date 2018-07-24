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
    public class GPOLocalGroupMapping
    {
        public string GPODisplayName { get; set; }

        public string GPOName { get; set; }

        public string GPOPath { get; set; }

        public string GPOType { get; set; }

        public IEnumerable<Filter> Filters { get; set; }

        public string GroupName { get; set; }

        public string GroupSID { get; set; }

        public IEnumerable<string> GroupMemberOf { get; set; }

        public IEnumerable<string> GroupMembers { get; set; }

        public string ObjectName { get; set; }

        public string ObjectDN { get; set; }

        public string[] ObjectSID { get; set; }

        public string Domain { get; set; }

        public bool IsGroup { get; set; }

        public string GPOGuid { get; set; }

        public string ContainerName { get; set; }

        public IEnumerable<string> ComputerName { get; set; }
    }
}
