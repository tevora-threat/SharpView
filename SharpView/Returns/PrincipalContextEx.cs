using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SharpView.Utils.NativeMethods;

namespace SharpView.Returns
{
    public class PrincipalContextEx
    {
        public System.DirectoryServices.AccountManagement.PrincipalContext Context { get; set; }

        public string Identity { get; set; }
    }
}
