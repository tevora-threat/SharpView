using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Enums
{
    [Flags]
    public enum TrustAttribute : UInt32
    {
        NON_TRANSITIVE  = 0x00000001,
        UPLEVEL_ONLY = 0x00000002,
        FILTER_SIDS = 0x00000004,
        FOREST_TRANSITIVE = 0x00000008,
        CROSS_ORGANIZATION= 0x00000010,
        WITHIN_FOREST= 0x00000020,
        TREAT_AS_EXTERNAL= 0x00000040,
        TRUST_USES_RC4_ENCRYPTION= 0x00000080,
        TRUST_USES_AES_KEYS= 0x00000100,
        CROSS_ORGANIZATION_NO_TGT_DELEGATION = 0x00000200,
        PIM_TRUST= 0x00000400
    }
}
