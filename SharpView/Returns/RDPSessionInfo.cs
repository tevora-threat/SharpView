using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SharpView.Utils.NativeMethods;

namespace SharpView.Returns
{
    public class RDPSessionInfo
    {
        public string ComputerName { get; set; }

        public string SessionName { get; set; }

        public string UserName { get; set; }

        public Int32 ID { get; set; }

        public WTS_CONNECTSTATE_CLASS State { get; set; }

        public string SourceIP { get; set; }
    }
}
