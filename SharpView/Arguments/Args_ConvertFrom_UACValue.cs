using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Arguments
{
    public class Args_ConvertFrom_UACValue
    {
        public int Value { get; set; }
        public int UAC { get { return Value; } set { Value = value; } }
        public int useraccountcontrol { get { return Value; } set { Value = value; } }

        public bool ShowAll { get; set; }
    }
}
