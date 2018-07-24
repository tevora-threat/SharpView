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
    public class ForeignGroupMember
    {
        public string GroupDomain { get; set; }

        public string GroupName { get; set; }

        public string GroupDistinguishedName { get; set; }

        public string MemberDomain { get; set; }

        public string MemberName { get; set; }

        public string MemberDistinguishedName { get; set; }
    }
}
