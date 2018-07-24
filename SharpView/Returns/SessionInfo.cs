using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SharpView.Utils.NativeMethods;

namespace SharpView.Returns
{
    public class SessionInfo
    {
        public string ComputerName { get; set; }
        public string CName { get; set; }
        public string UserName { get; set; }
        public uint Time { get; set; }
        public uint IdleTime { get; set; }
    }
}
