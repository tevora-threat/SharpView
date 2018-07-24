using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Enums
{
    public enum ADSNameType
    {
        DN                =   ActiveDs.ADS_NAME_TYPE_ENUM.ADS_NAME_TYPE_1779,  // CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com
        Canonical         =   ActiveDs.ADS_NAME_TYPE_ENUM.ADS_NAME_TYPE_CANONICAL,  // fabrikam.com/Engineers/Phineas Flynn
        NT4               =   ActiveDs.ADS_NAME_TYPE_ENUM.ADS_NAME_TYPE_NT4,  // fabrikam\pflynn
        Display           =   ActiveDs.ADS_NAME_TYPE_ENUM.ADS_NAME_TYPE_DISPLAY,  // pflynn
        DomainSimple      =   ActiveDs.ADS_NAME_TYPE_ENUM.ADS_NAME_TYPE_DOMAIN_SIMPLE,  // pflynn@fabrikam.com
        EnterpriseSimple  =   ActiveDs.ADS_NAME_TYPE_ENUM.ADS_NAME_TYPE_ENTERPRISE_SIMPLE,  // pflynn@fabrikam.com
        GUID              =   ActiveDs.ADS_NAME_TYPE_ENUM.ADS_NAME_TYPE_GUID,  // {95ee9fff-3436-11d1-b2b0-d15ae3ac8436}
        Unknown           =   ActiveDs.ADS_NAME_TYPE_ENUM.ADS_NAME_TYPE_UNKNOWN,  // unknown type - let the server do translation
        UPN               =   ActiveDs.ADS_NAME_TYPE_ENUM.ADS_NAME_TYPE_USER_PRINCIPAL_NAME,  // pflynn@fabrikam.com
        CanonicalEx       =   ActiveDs.ADS_NAME_TYPE_ENUM.ADS_NAME_TYPE_CANONICAL_EX, // fabrikam.com/Users/Phineas Flynn
        SPN               =   ActiveDs.ADS_NAME_TYPE_ENUM.ADS_NAME_TYPE_SERVICE_PRINCIPAL_NAME, // HTTP/kairomac.contoso.com
        SID               =   ActiveDs.ADS_NAME_TYPE_ENUM.ADS_NAME_TYPE_SID_OR_SID_HISTORY_NAME  // S-1-5-21-12986231-600641547-709122288-57999
    }
}
