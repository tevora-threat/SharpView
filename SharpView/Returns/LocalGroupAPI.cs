using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SharpView.Utils.NativeMethods;

namespace SharpView.Returns
{
    public class LocalGroupAPI
    {
        public string ComputerName { get; set; }
        public string GroupName { get; set; }
        public string Comment { get; set; }
    }
}
