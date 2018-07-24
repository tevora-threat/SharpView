using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public class StringArrayConverter : ArrayConverter
    {
        public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
        {
            if (sourceType == typeof(string))
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
                return ((string)value).Split(',');
            }

            return base.ConvertFrom(context, culture, value);
        }
    }
}
