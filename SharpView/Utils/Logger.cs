using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public static class Logger
    {
        public static void Write_Verbose(string log, bool endLine = true)
        {
            if (endLine)
            {
                System.Diagnostics.Debug.WriteLine(log);
                Console.WriteLine(log);
            }
            else
            {
                System.Diagnostics.Debug.Write(log);
                Console.Write(log);
            }
        }

        public static void Write_Warning(string log, bool endLine = true)
        {
            if (endLine)
            {
                System.Diagnostics.Debug.WriteLine(log);
                Console.WriteLine(log);
            }
            else
            {
                System.Diagnostics.Debug.Write(log);
                Console.Write(log);
            }
        }

        public static void Write_Output(string log, bool endLine = true)
        {
            if (endLine)
            {
                System.Diagnostics.Debug.WriteLine(log);
                Console.WriteLine(log);
            }
            else
            {
                System.Diagnostics.Debug.Write(log);
                Console.Write(log);
            }
        }
    }
}
