using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class UserLocation
    {
        public string UserDomain { get; set; }
        public string UserName { get; set; }
        public string ComputerName { get; set; }
        public string IPAddress { get; set; }
        public string SessionFrom { get; set; }
        public string SessionFromName { get; set; }
        public bool LocalAdmin { get; set; }
    }
}
