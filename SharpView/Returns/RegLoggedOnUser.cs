using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class RegLoggedOnUser
    {
        public string ComputerName { get; set; }

        public string UserDomain { get; set; }

        public string UserName { get; set; }

        public string UserSID { get; set; }
    }
}
