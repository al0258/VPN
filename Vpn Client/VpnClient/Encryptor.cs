using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace VpnClient
{
    class Encryptor
    {//Class that uses aes cryptography to encrypt and decrypt data
        private MemoryStream ms;
        private byte[] key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
        private byte[] IV = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
        private TripleDESCryptoServiceProvider tdes;
        private CryptoStream cswEnc;
        private CryptoStream cswDec;

        public Encryptor()
        {
            this.ms = new MemoryStream();
            this.tdes = new TripleDESCryptoServiceProvider();
            this.cswEnc = new CryptoStream(ms, tdes.CreateEncryptor(key, IV), CryptoStreamMode.Write);
            this.cswDec = new CryptoStream(ms, tdes.CreateDecryptor(key, IV), CryptoStreamMode.Write);
        }

        public byte[] EncryptData(byte[] byteBuffer)
        {//The Function recieving data encrypting it and return it
            ms.Position = 0;
            cswEnc.Write(byteBuffer, 0, byteBuffer.Length);
            try
            {
                cswEnc.FlushFinalBlock();
            }
            catch { }
            return (ms.GetBuffer());
        }

        public byte[] DecryptData(NetworkStream netStream)
        {//The Function receiving encrypted data and decrypting it and return
            ms.Position = 0;
            byte[] data = new byte[2048];
            int offset = 0;
            int size;

            do
            {
                int recv = netStream.Read(data, offset, 1);
                size = BitConverter.ToInt32(data, offset);
                if (size > 0)
                    cswDec.Write(data, offset, 1);
                offset++;
            } while (size > 0);

            try
            {
                cswDec.FlushFinalBlock();
            }
            catch { }
            return ms.GetBuffer();
        }
    }
}
