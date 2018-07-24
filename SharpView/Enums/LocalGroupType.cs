using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Enums
{
    public enum LocalGroupType
    {
        [Description("Administrators")]
        Administrators,
        [Description("S-1-5-32-544")]
        S_1_5_32_544,
        [Description("RDP")]
        RDP,
        [Description("Remote Desktop Users")]
        RemoteDesktopUsers,
        [Description("S-1-5-32-555")]
        S_1_5_32_555
    }
}
