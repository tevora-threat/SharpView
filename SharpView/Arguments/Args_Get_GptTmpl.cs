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
    public class Args_Get_GptTmpl
    {
        public string GptTmplPath { get; set; }
        public string gpcfilesyspath { get { return GptTmplPath; } set { GptTmplPath = value; } }
        public string Path { get { return GptTmplPath; } set { GptTmplPath = value; } }

        public NetworkCredential Credential { get; set; }
    }
}
