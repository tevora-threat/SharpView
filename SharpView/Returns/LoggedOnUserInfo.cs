using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SharpView.Utils.NativeMethods;

namespace SharpView.Returns
{
    public class LoggedOnUserInfo
    {
        public string UserName { get; set; }
        public string LogonDomain { get; set; }
        public string AuthDomains { get; set; }
        public string LogonServer { get; set; }
        public string ComputerName { get; set; }
    }
}
