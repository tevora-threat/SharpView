using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class GptTmpl : Dictionary<string, Dictionary<string, object>>
    {
        public string Path { get; set; }

        public GptTmpl()
        {

        }

        public GptTmpl(Dictionary<string, Dictionary<string, object>> obj)
        {
            foreach (var value in obj)
            {
                Add(value.Key, value.Value);
            }
        }
    }
}
