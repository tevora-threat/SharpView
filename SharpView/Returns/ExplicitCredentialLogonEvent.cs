using SharpView.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class ExplicitCredentialLogonEvent : IWinEvent
    {
        public string ComputerName { get; set; }

        public DateTime? TimeCreated { get; set; }

        public int EventId { get; set; }

        public string SubjectDomainName { get; set; }

        public string SubjectLogonId { get; set; }

        public string SubjectUserName { get; set; }

        public string SubjectUserSid { get; set; }

        public string TargetDomainName { get; set; }

        public string TargetLogonId { get; set; }

        public string TargetLogonGuid { get; set; }

        public string TargetUserName { get; set; }

        public string TargetUserSid { get; set; }

        public string TargetServerName { get; set; }

        public string LogonGuid { get; set; }

        public string TargetInfo { get; set; }

        public string ProcessId { get; set; }

        public string ProcessName { get; set; }

        public string IpAddress { get; set; }

        public string IpPort { get; set; }
    }
}
