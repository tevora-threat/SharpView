using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public static class ResultPropertyValueCollectionExtension
    {
        public static IEnumerable<T> GetValues<T>(this ResultPropertyValueCollection collection)
        {
            var values = new List<T>();
            foreach (T value in collection)
            {
                values.Add(value);
            }
            return values;
        }
    }
}
