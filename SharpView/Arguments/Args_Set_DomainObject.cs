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
    public class Args_Set_DomainObject
    {
        public string[] Identity { get; set; }
        public string[] DistinguishedName { get { return Identity; } set { Identity = value; } }
        public string[] SamAccountName { get { return Identity; } set { Identity = value; } }
        public string[] Name { get { return Identity; } set { Identity = value; } }

        public Dictionary<string, object> Set { get; set; }
        public Dictionary<string, object> Replace { get { return Set; } set { Set = value; } }

        public Dictionary<string, object> XOR { get; set; }

        public string[] Clear { get; set; }

        public string Domain { get; set; }

        public string LDAPFilter { get; set; }
        public string Filter { get { return LDAPFilter; } set { LDAPFilter = value; } }

        public string SearchBase { get; set; }
        public string ADSPath { get { return SearchBase; } set { SearchBase = value; } }

        public string Server { get; set; }
        public string DomainController { get { return Server; } set { Server = value; } }

        public SearchScope SearchScope { get; set; } = SearchScope.Subtree;

        private int _ResultPageSize = 200;
        public int ResultPageSize
        {
            get { return _ResultPageSize; }
            set
            {
                if (value < 1 || value > 10000) throw new ArgumentOutOfRangeException("ResultPageSize");
                _ResultPageSize = value;
            }
        }

        private int? _ServerTimeLimit;
        public int? ServerTimeLimit
        {
            get { return _ServerTimeLimit; }
            set
            {
                if (value < 1 || value > 10000) throw new ArgumentOutOfRangeException("ServerTimeLimit");
                _ServerTimeLimit = value;
            }
        }

        public bool Tombstone { get; set; }

        public NetworkCredential Credential { get; set; }
    }
}
