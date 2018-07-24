using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Enums
{
    [Flags]
    public enum GroupType : Int32
    {
        CREATED_BY_SYSTEM = 0x00000001,
        GLOBAL_SCOPE = ActiveDs.ADS_GROUP_TYPE_ENUM.ADS_GROUP_TYPE_GLOBAL_GROUP,
        DOMAIN_LOCAL_SCOPE = ActiveDs.ADS_GROUP_TYPE_ENUM.ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP,
        UNIVERSAL_SCOPE = ActiveDs.ADS_GROUP_TYPE_ENUM.ADS_GROUP_TYPE_UNIVERSAL_GROUP,
        APP_BASIC = 0x00000010,
        APP_QUERY = 0x00000020,
        SECURITY = ActiveDs.ADS_GROUP_TYPE_ENUM.ADS_GROUP_TYPE_SECURITY_ENABLED
    }
}
