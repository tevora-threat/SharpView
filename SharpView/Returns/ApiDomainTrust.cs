using SharpView.Interfaces;
using SharpView.Utils;
using System;

namespace SharpView.Returns
{
    public class ApiDomainTrust : IDomainTrust
    {
        public string SourceName { get; set; }

        public string TargetName { get; set; }

        public string TargetNetbiosName { get; set; }

        public uint Flags { get; set; }

        public uint ParentIndex { get; set; }

        public NativeMethods.DS_DOMAIN_TRUST_TYPE TrustType { get; set; }

        public uint TrustAttributes { get; set; }

        public string TargetSid { get; set; }

        public Guid TargetGuid { get; set; }
    }
}
