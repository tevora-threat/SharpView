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
    public class ManagedSecurityGroup
    {
        public string GroupName { get; set; }

        public string GroupDistinguishedName { get; set; }

        public string ManagerName { get; set; }

        public string ManagerDistinguishedName { get; set; }

        public ManagerType? ManagerType { get; set; }

        public string ManagerCanWrite { get; set; }
    }
}
