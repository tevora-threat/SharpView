using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class ACL : ResolvedSID
    {
        public string ObjectDN { get; set; }

        public GenericAce Ace { get; set; }
        
        public string ObjectSID { get; set; }

        public System.DirectoryServices.ActiveDirectoryRights ActiveDirectoryRights { get; set; }
    }
}
