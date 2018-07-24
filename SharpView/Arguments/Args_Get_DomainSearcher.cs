using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Arguments
{
    public class Args_Get_DomainSearcher
    {
        public string Domain { get; set; }

        public string LDAPFilter { get; set; }
        public string Filter { get { return LDAPFilter; } set { LDAPFilter = value; } }

        public string[] Properties { get; set; }

        public string SearchBase { get; set; }
        public string ADSPath { get { return SearchBase; } set { SearchBase = value; } }

        public string SearchBasePrefix { get; set; }

        public string Server { get; set; }
        public string DomainController { get { return Server; } set { Server = value; } }

        public SearchScope SearchScope { get; set; } = SearchScope.Subtree;

        private int _ResultPageSize = 200;
        public int ResultPageSize {
            get { return _ResultPageSize; }
            set {
                if (value < 1 || value > 10000) throw new ArgumentOutOfRangeException("ResultPageSize");
                _ResultPageSize = value;
            }
        }

        private int? _ServerTimeLimit = 120;
        public int? ServerTimeLimit
        {
            get { return _ServerTimeLimit; }
            set
            {
                if (value < 1 || value > 10000) throw new ArgumentOutOfRangeException("ServerTimeLimit");
                _ServerTimeLimit = value;
            }
        }

        public SecurityMasks? SecurityMasks { get; set; }

        public bool Tombstone { get; set; }
        
        public NetworkCredential Credential { get; set; }
    }
}
