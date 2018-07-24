using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SharpView.Utils.NativeMethods;

namespace SharpView.Returns
{
    public class LocalGroupMemberAPI
    {
        public string ComputerName { get; set; }
        public string GroupName { get; set; }
        public string MemberName { get; set; }
        public string SID { get; set; }
        public bool IsGroup { get; set; }
        public string IsDomain { get; set; }
    }
}
