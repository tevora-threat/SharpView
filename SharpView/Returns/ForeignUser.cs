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
    public class ForeignUser
    {
        public string UserDomain { get; set; }

        public string UserName { get; set; }

        public string UserDistinguishedName { get; set; }

        public string GroupDomain { get; set; }

        public string GroupName { get; set; }

        public string GroupDistinguishedName { get; set; }
    }
}
