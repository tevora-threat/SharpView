using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public static class WildcardMatch
    {
        #region Public Methods
        public static bool IsLike(string pattern, string text, bool caseSensitive = false)
        {
            pattern = pattern.Replace(".", @"\.");
            pattern = pattern.Replace("?", ".");
            pattern = pattern.Replace("*", ".*?");
            pattern = pattern.Replace(@"\", @"\\");
            pattern = pattern.Replace(" ", @"\s");
            return new Regex(pattern, caseSensitive ? RegexOptions.None : RegexOptions.IgnoreCase).IsMatch(text);
        }

        public static bool IsLikeMatch(this string text, string pattern)
        {
            return IsLike(pattern, text);
        }

        public static IEnumerable<string> GetMatches(this ICollection collection, string pattern)
        {
            var matches = new List<string>();
            foreach (string item in collection)
            {
                if (item.IsLikeMatch(pattern))
                    matches.Add(item);
            }
            return matches;
        }

        public static string GetFirstMatch(this ICollection collection, string pattern)
        {
            foreach (string item in collection)
            {
                if (item.IsLikeMatch(pattern))
                    return item;
            }
            return null;
        }
        #endregion
    }
}
