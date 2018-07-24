using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class DomainPolicyData : GptTmpl
    {
        public string GPOName { get; set; }

        public string GPODisplayName { get; set; }

        public DomainPolicyData()
        {

        }

        public DomainPolicyData(Dictionary<string, Dictionary<string, object>> obj) : base(obj)
        {
        }
    }
}
