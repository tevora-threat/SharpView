using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class CachedRDPConnection
    {
        public string ComputerName { get; set; }

        public string UserName { get; set; }

        public string UserSID { get; set; }

        public string TargetServer { get; set; }

        public string UsernameHint { get; set; }
    }
}
