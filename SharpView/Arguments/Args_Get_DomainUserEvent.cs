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
    public class Args_Get_DomainUserEvent
    {
        public string[] ComputerName { get; set; } = new[] { Environment.GetEnvironmentVariable("COMPUTERNAME") };
        public string[] dnshostname { get { return ComputerName; } set { ComputerName = value; } }
        public string[] HostName { get { return ComputerName; } set { ComputerName = value; } }
        public string[] name { get { return ComputerName; } set { ComputerName = value; } }

        public DateTime StartTime { get; set; } = DateTime.Now.AddDays(-1);

        public DateTime EndTime { get; set; } = DateTime.Now;

        private int _MaxEvents = 5000;
        public int MaxEvents
        {
            get { return _MaxEvents; }
            set
            {
                if (value < 1 || value > 1000000) throw new ArgumentOutOfRangeException(nameof(MaxEvents));
                _MaxEvents = value;
            }
        }

        public NetworkCredential Credential { get; set; }
    }
}
