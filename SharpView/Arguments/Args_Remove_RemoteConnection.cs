using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using SharpView.Utils;

namespace SharpView.Arguments
{
    public class Args_Remove_RemoteConnection
    {
        public string[] ComputerName { get; set; }
        public string[] HostName { get { return ComputerName; } set { ComputerName = value; } }
        public string[] dnshostname { get { return ComputerName; } set { ComputerName = value; } }
        public string[] name { get { return ComputerName; } set { ComputerName = value; } }

        public string[] _path;
        public string[] Path
        {
            get
            {
                return _path;
            }
            set
            {
                if (value != null)
                {
                    foreach (var item in value)
                    {
                        if (!item.IsRegexMatch(@"\\\\.*\\.*"))
                            throw new ArgumentException(@"Should be '\\\\.*\\.*' as pattern", nameof(Path));
                    }
                }
                _path = value;
            }
        }
    }
}
