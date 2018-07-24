using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SharpView.Utils.NativeMethods;

namespace SharpView.Returns
{
    public class ShareInfo
    {
        public string Name { get; set; }
        public uint Type { get; set; }
        public string Remark { get; set; }
        public string ComputerName { get; set; }
    }
}
