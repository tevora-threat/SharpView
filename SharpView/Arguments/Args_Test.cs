using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Arguments
{

    public class Args_Test
    {
        public bool TestBool { get; set; }
        public string TestString { get; set; }
        public string[] TestStringArray { get; set; }
        public GroupType TestIntEnum { get; set; }
        public Rights TestEnum { get; set; }
        public Rights? TestPointEnum { get; set; }
        public System.Net.NetworkCredential Credential { get; set; }
    }
}
