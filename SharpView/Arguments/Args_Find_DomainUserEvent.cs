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
    public class Args_Find_DomainUserEvent
    {
        public string[] ComputerName { get; set; }
        public string[] dnshostname { get { return ComputerName; } set { ComputerName = value; } }
        public string[] HostName { get { return ComputerName; } set { ComputerName = value; } }
        public string[] name { get { return ComputerName; } set { ComputerName = value; } }

        public string Domain { get; set; }

        public Dictionary<string, string> Filter { get; set; }

        public DateTime StartTime { get; set; } = DateTime.Now.AddDays(-1);

        public DateTime EndTime { get; set; } = DateTime.Now;

        private int _MaxEvents = 200;
        public int MaxEvents
        {
            get { return _MaxEvents; }
            set
            {
                if (value < 1 || value > 1000000) throw new ArgumentOutOfRangeException("MaxEvents");
                _MaxEvents = value;
            }
        }

        public string[] UserIdentity { get; set; }

        public string UserDomain { get; set; }

        public string UserLDAPFilter { get; set; }

        public string UserSearchBase { get; set; }

        public string[] UserGroupIdentity { get; set; } = { "Domain Admins" };
        public string[] GroupName { get { return UserGroupIdentity; } set { UserGroupIdentity = value; } }
        public string[] Group { get { return UserGroupIdentity; } set { UserGroupIdentity = value; } }

        public bool UserAdminCount { get; set; }
        public bool AdminCount { get { return UserAdminCount; } set { UserAdminCount = value; } }

        public bool CheckAccess { get; set; }

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

        public bool StopOnSuccess { get; set; }

        private int _Delay = 0;
        public int Delay
        {
            get { return _Delay; }
            set
            {
                if (value < 1 || value > 10000) throw new ArgumentOutOfRangeException("Delay");
                _Delay = value;
            }
        }

        private double _Jitter = 0.3;
        public double Jitter
        {
            get { return _Jitter; }
            set
            {
                if (value < 0.0 || value > 1.0) throw new ArgumentOutOfRangeException("Jitter");
                _Jitter = value;
            }
        }

        private int _Threads = 20;
        public int Threads
        {
            get { return _Threads; }
            set
            {
                if (value < 1 || value > 100) throw new ArgumentOutOfRangeException("Threads");
                _Threads = value;
            }
        }
    }
}
