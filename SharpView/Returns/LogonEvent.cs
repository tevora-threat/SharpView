using SharpView.Interfaces;
using System;

namespace SharpView.Returns
{
    public class LogonEvent : IWinEvent
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

        public string TargetUserName { get; set; }

        public string TargetUserSid { get; set; }

        public string LogonType { get; set; }
        
        public string LogonProcessName { get; set; }

        public string LogonGuid { get; set; }

        public string AuthenticationPackageName { get; set; }

        public string WorkstationName { get; set; }

        public string TransmittedServices { get; set; }

        public string LmPackageName { get; set; }

        public string KeyLength { get; set; }

        public string ProcessId { get; set; }

        public string ProcessName { get; set; }

        public string IpAddress { get; set; }

        public string IpPort { get; set; }

        public string ImpersonationLevel { get; set; }

        public string RestrictedAdminMode { get; set; }

        public string TargetOutboundUserName { get; set; }

        public string TargetOutboundDomainName { get; set; }

        public string VirtualAccount { get; set; }

        public string TargetLinkedLogonId { get; set; }

        public string ElevatedToken { get; set; }
    }
}
