using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class ResolvedSID
    {
        public string IdentityReferenceName { get; set; }

        public string IdentityReferenceDomain { get; set; }

        public string IdentityReferenceDN { get; set; }

        public string IdentityReferenceClass { get; set; }
    }
}
