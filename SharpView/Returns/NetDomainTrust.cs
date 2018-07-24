using SharpView.Interfaces;
using System.DirectoryServices.ActiveDirectory;

namespace SharpView.Returns
{
    public class NetDomainTrust : IDomainTrust
    {
        public string SourceName { get; set; }
        public string TargetName { get; set; }
        public TrustDirection TrustDirection { get; set; }
        public TrustType TrustType { get; set; }
    }
}
