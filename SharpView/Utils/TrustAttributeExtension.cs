using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public static class TrustAttributeExtension
    {
        public static IEnumerable<TrustAttribute> ExtractValues(this TrustAttribute attr)
        {
            var ui32 = (UInt32)attr;
            var values = new List<TrustAttribute>();
            for (int i = 0; i < ui32; i++)
            {
                var val = ui32 & ((UInt64)1 << i);
                if (val != 0)
                    values.Add((TrustAttribute)val);
            }
            return values;
        }
    }
}
