using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Arguments
{
    public class Args_Invoke_UserImpersonation
    {
        public NetworkCredential Credential { get; set; }

        public IntPtr TokenHandle { get; set; }

        public bool Quiet { get; set; }
    }
}
