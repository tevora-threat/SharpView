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
    public class GPOGroup
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
    }
}
