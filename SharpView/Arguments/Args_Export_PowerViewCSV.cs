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
    public class Args_Export_PowerViewCSV
    {
        public object[] InputObject { get; set; }

        public string Path { get; set; }

        public Char Delimiter { get; set; } = ',';

        public bool Append { get; set; }
    }
}
