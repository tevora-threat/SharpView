using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public static class ReflectionExtension
    {
        public static T GetPropValue<T>(this object obj, string propName)
        {
            return (T)obj.GetType().GetProperty(propName)?.GetValue(obj, null);
        }
    }
}
