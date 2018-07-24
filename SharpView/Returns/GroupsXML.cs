using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class GroupsXML
    {
        public string GPOPath { get; set; }

        public IEnumerable<Filter> Filters { get; set; }

        public string GroupName { get; set; }

        public string GroupSID { get; set; }

        public IEnumerable<string> GroupMemberOf { get; set; }

        public IEnumerable<string> GroupMembers { get; set; }
    }
}
