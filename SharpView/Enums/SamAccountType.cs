using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Enums
{
    public enum SamAccountType : Int32
    {
        DOMAIN_OBJECT = 0x00000000,
        GROUP_OBJECT = 0x10000000,
        NON_SECURITY_GROUP_OBJECT = 0x10000001,
        ALIAS_OBJECT = 0x20000000,
        NON_SECURITY_ALIAS_OBJECT = 0x20000001,
        USER_OBJECT = 0x30000000,
        MACHINE_ACCOUNT = 0x30000001,
        TRUST_ACCOUNT = 0x30000002,
        APP_BASIC_GROUP = 0x40000000,
        APP_QUERY_GROUP = 0x40000001,
        ACCOUNT_TYPE_MAX = 0x7fffffff
    }
}
