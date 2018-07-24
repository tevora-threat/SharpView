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
    public class Args_Add_DomainObjectAcl
    {
        public string[] TargetIdentity { get; set; }
        public string[] DistinguishedName { get { return TargetIdentity; } set { TargetIdentity = value; } }
        public string[] SamAccountName { get { return TargetIdentity; } set { TargetIdentity = value; } }
        public string[] Name { get { return TargetIdentity; } set { TargetIdentity = value; } }

        public string TargetDomain { get; set; }

        public string TargetLDAPFilter { get; set; }
        public string Filter { get { return TargetLDAPFilter; } set { TargetLDAPFilter = value; } }

        public string TargetSearchBase { get; set; }

        public string[] PrincipalIdentity { get; set; }

        public string PrincipalDomain { get; set; }

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

        public Rights? Rights { get; set; } = Enums.Rights.All;

        public Guid RightsGUID { get; set; }
    }
}
