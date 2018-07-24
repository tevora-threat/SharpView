using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public static class TestConnection
    {
        public static bool Ping(string host, int count = 1)
        {
            Ping pingSender = new Ping();
            PingOptions options = new PingOptions();

            options.DontFragment = true;

            byte[] data = { 0x20, 0x20 };
            int timeout = 120;

            for (int i = 0; i < count; i++)
            {
                try
                {
                    PingReply reply = pingSender.Send(host, timeout, data, options);
                    if (reply.Status == IPStatus.Success)
                    {
                        return true;
                    }
                }
                catch
                {
                }
            }

            return false;
        }
    }
}
