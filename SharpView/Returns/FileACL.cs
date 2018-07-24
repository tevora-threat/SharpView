using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;
using static SharpView.Utils.NativeMethods;

namespace SharpView.Returns
{
    public class FileACL
    {
        public string Path { get; set; }
        public string FileSystemRights { get; set; }
        public IEnumerable<string> IdentityReference { get; set; }
        public string IdentitySID { get; set; }
        public AccessControlType AccessControlType { get; set; }
    }
}
