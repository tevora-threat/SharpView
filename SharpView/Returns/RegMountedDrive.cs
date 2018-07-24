using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class RegMountedDrive
    {
        public string ComputerName { get; set; }

        public string UserName { get; set; }

        public string UserSID { get; set; }

        public string DriveLetter { get; set; }

        public string ProviderName { get; set; }

        public string RemotePath { get; set; }

        public string DriveUserName { get; set; }
    }
}
