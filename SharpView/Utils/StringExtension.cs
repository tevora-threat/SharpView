using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public static class StringExtension
    {
        public static string ShortenString(this string s, int length)
        {
            string ret;
            if (s.Length > length)
            {
                ret = s.Substring(0, length - 3);
                ret = ret.PadRight(length, '.');
            }
            else
                ret = s;

            ret = ret.PadRight(length, ' ');
            return ret;
        }

        public static string ToJoinedString(this string[] ss, string separator = ",")
        {
            return string.Join(separator, ss);
        }

        public static bool ContainsNoCase(this string[] ss, string pattern)
        {
            return ss.Any(x => x.Equals(pattern, StringComparison.OrdinalIgnoreCase));
        }
    }
}
