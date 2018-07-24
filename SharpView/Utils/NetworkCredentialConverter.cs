using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public class NetworkCredentialConverter : TypeConverter
    {
        public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
        {
            if (sourceType == typeof(System.Net.NetworkCredential))
            {
                return true;
            }

            return base.CanConvertFrom(context, sourceType);
        }

        public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
        {
            string s = value as string;

            if (!string.IsNullOrEmpty(s))
            {
                string user = string.Empty, password = string.Empty;
                var posPass = s.IndexOf("/");
                if (posPass >= 0)
                {
                    user = s.Substring(0, posPass);
                    password = s.Substring(posPass + 1);
                }
                else user = s;
                return new System.Net.NetworkCredential(user, password);
            }

            return base.ConvertFrom(context, culture, value);
        }
    }
}
