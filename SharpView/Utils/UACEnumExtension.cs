using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public static class UACEnumExtension
    {
        public static IEnumerable<UACEnum> ExtractValues(this UACEnum uac)
        {
            var ui64 = (UInt64)uac;
            var values = new List<UACEnum>();
            for (int i = 0; i < 64; i++)
            {
                var val = ui64 & ((UInt64)1 << i);
                if (val != 0)
                    values.Add((UACEnum)val);
            }
            return values;
        }

        public static UACEnumValue GetValue(this UACEnum uac)
        {
            switch (uac)
            {
                case UACEnum.SCRIPT:
                case UACEnum.NOT_SCRIPT:
                    return UACEnumValue.SCRIPT;
                case UACEnum.ACCOUNTDISABLE:
                case UACEnum.NOT_ACCOUNTDISABLE:
                    return UACEnumValue.ACCOUNTDISABLE;
                case UACEnum.HOMEDIR_REQUIRED:
                case UACEnum.NOT_HOMEDIR_REQUIRED:
                    return UACEnumValue.HOMEDIR_REQUIRED;
                case UACEnum.LOCKOUT:
                case UACEnum.NOT_LOCKOUT:
                    return UACEnumValue.LOCKOUT;
                case UACEnum.PASSWD_NOTREQD:
                case UACEnum.NOT_PASSWD_NOTREQD:
                    return UACEnumValue.PASSWD_NOTREQD;
                case UACEnum.PASSWD_CANT_CHANGE:
                case UACEnum.NOT_PASSWD_CANT_CHANGE:
                    return UACEnumValue.PASSWD_CANT_CHANGE;
                case UACEnum.ENCRYPTED_TEXT_PWD_ALLOWED:
                case UACEnum.NOT_ENCRYPTED_TEXT_PWD_ALLOWED:
                    return UACEnumValue.ENCRYPTED_TEXT_PWD_ALLOWED;
                case UACEnum.TEMP_DUPLICATE_ACCOUNT:
                case UACEnum.NOT_TEMP_DUPLICATE_ACCOUNT:
                    return UACEnumValue.TEMP_DUPLICATE_ACCOUNT;
                case UACEnum.NORMAL_ACCOUNT:
                case UACEnum.NOT_NORMAL_ACCOUNT:
                    return UACEnumValue.NORMAL_ACCOUNT;
                case UACEnum.INTERDOMAIN_TRUST_ACCOUNT:
                case UACEnum.NOT_INTERDOMAIN_TRUST_ACCOUNT:
                    return UACEnumValue.INTERDOMAIN_TRUST_ACCOUNT;
                case UACEnum.WORKSTATION_TRUST_ACCOUNT:
                case UACEnum.NOT_WORKSTATION_TRUST_ACCOUNT:
                    return UACEnumValue.WORKSTATION_TRUST_ACCOUNT;
                case UACEnum.SERVER_TRUST_ACCOUNT:
                case UACEnum.NOT_SERVER_TRUST_ACCOUNT:
                    return UACEnumValue.SERVER_TRUST_ACCOUNT;
                case UACEnum.DONT_EXPIRE_PASSWORD:
                case UACEnum.NOT_DONT_EXPIRE_PASSWORD:
                    return UACEnumValue.DONT_EXPIRE_PASSWORD;
                case UACEnum.MNS_LOGON_ACCOUNT:
                case UACEnum.NOT_MNS_LOGON_ACCOUNT:
                    return UACEnumValue.MNS_LOGON_ACCOUNT;
                case UACEnum.SMARTCARD_REQUIRED:
                case UACEnum.NOT_SMARTCARD_REQUIRED:
                    return UACEnumValue.SMARTCARD_REQUIRED;
                case UACEnum.TRUSTED_FOR_DELEGATION:
                case UACEnum.NOT_TRUSTED_FOR_DELEGATION:
                    return UACEnumValue.TRUSTED_FOR_DELEGATION;
                case UACEnum.NOT_DELEGATED:
                case UACEnum.NOT_NOT_DELEGATED:
                    return UACEnumValue.NOT_DELEGATED;
                case UACEnum.USE_DES_KEY_ONLY:
                case UACEnum.NOT_USE_DES_KEY_ONLY:
                    return UACEnumValue.USE_DES_KEY_ONLY;
                case UACEnum.DONT_REQ_PREAUTH:
                case UACEnum.NOT_DONT_REQ_PREAUTH:
                    return UACEnumValue.DONT_REQ_PREAUTH;
                case UACEnum.PASSWORD_EXPIRED:
                case UACEnum.NOT_PASSWORD_EXPIRED:
                    return UACEnumValue.PASSWORD_EXPIRED;
                case UACEnum.TRUSTED_TO_AUTH_FOR_DELEGATION:
                case UACEnum.NOT_TRUSTED_TO_AUTH_FOR_DELEGATION:
                    return UACEnumValue.TRUSTED_TO_AUTH_FOR_DELEGATION;
                case UACEnum.PARTIAL_SECRETS_ACCOUNT:
                case UACEnum.NOT_PARTIAL_SECRETS_ACCOUNT:
                    return UACEnumValue.PARTIAL_SECRETS_ACCOUNT;
                default:
                    break;
            }
            return 0;
        }

        public static UInt32 GetValueAsInteger(this UACEnum uac)
        {
            var val = uac.GetValue();
            return (UInt32)val;
        }

        public static bool IsNot(this UACEnum uac)
        {
            return uac.ToString().IndexOf("NOT_") == 0 && uac != UACEnum.NOT_DELEGATED;
        }
    }
}
