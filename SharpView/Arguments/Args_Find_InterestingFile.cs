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
    public class Args_Find_InterestingFile
    {
        public string[] Path { get; set; } = { @".\" };

        public string[] Include { get; set; } = { @"*password*", @"*sensitive*", @"*admin*", @"*login*", @"*secret*", @"unattend*.xml", @"*.vmdk", @"*creds*", @"*credential*", @"*.config" };
        public string[] SearchTerms { get { return Include; } set { Include = value; } }
        public string[] Terms { get { return Include; } set { Include = value; } }

        public DateTime? LastAccessTime { get; set; }

        public DateTime? LastWriteTime { get; set; }

        public DateTime? CreationTime { get; set; }

        public bool OfficeDocs { get; set; }

        public bool FreshEXEs { get; set; }

        public bool ExcludeFolders { get; set; }

        public bool ExcludeHidden { get; set; }

        public bool CheckWriteAccess { get; set; }

        public NetworkCredential Credential { get; set; }
    }
}
