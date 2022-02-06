using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VpnServer
{
    public class AidFunctions
    {
        public AidFunctions()
        {

        }

        public string AddDots(string mac)
        {
            string newMac = mac;
            for (int i = 2; i < mac.Length + 3; i += 3)
            {
                newMac = newMac.Insert(i, ":");
            }
            return newMac;
        }

        public byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
