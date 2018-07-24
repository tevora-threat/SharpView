using SharpView.Enums;
using SharpView.Interfaces;
using System.DirectoryServices.ActiveDirectory;

namespace SharpView.Returns
{
    public class LdapDomainTrust : IDomainTrust
    {
        public string SourceName { get; set; }

        public string TargetName { get; set; }

        public TrustType TrustType { get; set; }

        public TrustDirection TrustDirection { get; set; }

        public TrustAttribute TrustAttributes { get; set; }

        public object WhenCreated { get; set; }

        public object WhenChanged { get; set; }
    }
}
