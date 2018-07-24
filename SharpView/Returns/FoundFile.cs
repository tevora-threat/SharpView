using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class FoundFile
    {
        public string Path { get; set; }
        public string Owner { get; set; }
        public DateTime LastAccessTime { get; set; }
        public DateTime LastWriteTime { get; set; }
        public DateTime CreationTime { get; set; }
        public long Length { get; set; }
    }
}
