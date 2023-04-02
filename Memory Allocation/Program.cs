using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using static Memory_Allocation.Program;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using static System.Collections.Specialized.BitVector32;
using System.Security.Cryptography;
using System.Security.Policy;
using Microsoft.Win32.SafeHandles;

namespace Memory_Allocation
{
    internal class Program
    {
        //[00]
        //SHELLCODE LOCATION
        //AllocADsMem
        //VirtualProtect            PAGE_EXECUTE_READWRITE
        //COPY MEMORY
        //EXECUTION FUNCTION
        //FreeADsMem
        /*
        public enum MEM_PAGE : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
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

        [DllImport("activeds.dll")]
        public static extern IntPtr AllocADsMem(
            int cb
        );

        [DllImport("activeds.dll")]
        public static extern bool FreeADsMem(
            IntPtr pMem
        );

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(
            IntPtr lpAddress,
            int dwSize,
            MEM_PAGE flNewProtect,
            out uint lpflOldProtect
        );
        */

        //[01]
        //SHELLCODE LOCATION
        //CoTaskMemAlloc
        //VirtualProtect            PAGE_EXECUTE_READWRITE
        //COPY MEMORY
        //EXECUTION FUNCTION
        //CoTaskMemFree
        /*
        public enum MEM_PAGE : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
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

        [DllImport("ole32.dll")]
        static extern IntPtr CoTaskMemAlloc(
            int cb
        );

        [DllImport("ole32.dll")]
        static extern void CoTaskMemFree(
            IntPtr ptr
        );

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(
            IntPtr lpAddress,
            int dwSize,
            MEM_PAGE flNewProtect,
            out uint lpflOldProtect
        );
        */

        //[02]
        //SHELLCODE LOCATION
        //CreateFileMapping         PAGE_EXECUTE_READWRITE
        //  OR  CreateFileMappingA
        //  OR  CreateFileMappingW
        //MapViewOfFile             Write|Execute
        //  NOR  MapViewOfFile2
        //  OR  MapViewOfFile3
        //  OR  MapViewOfFileEx
        //COPY MEMORY
        //EXECUTION FUNCTION
        //UnmapViewOfFile
        /*
        public enum MEM_PAGE : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
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
        public enum FileMapAccessType : uint
        {
            Copy = 0x01,
            Write = 0x02,
            Read = 0x04,
            AllAccess = 0x08,
            Execute = 0x20,
        }

        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateFileMapping(
            IntPtr hFile,
            IntPtr lpFileMappingAttributes,
            MEM_PAGE flProtect,
            uint dwMaximumSizeHigh,
            uint dwMaximumSizeLow,
            string lpName
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateFileMappingA(
            IntPtr hFile,
            IntPtr lpFileMappingAttributes,
            MEM_PAGE flProtect,
            uint dwMaximumSizeHigh,
            uint dwMaximumSizeLow,
            string lpName
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateFileMappingW(
            IntPtr hFile,
            IntPtr lpFileMappingAttributes,
            MEM_PAGE flProtect,
            uint dwMaximumSizeHigh,
            uint dwMaximumSizeLow,
            string lpName
        );

        [DllImport("kernel32.dll")]
        public static extern IntPtr MapViewOfFile(
            IntPtr hFileMappingObject,
            FileMapAccessType dwDesiredAccess,
            uint dwFileOffsetHigh,
            uint dwFileOffsetLow,
            uint dwNumberOfBytesToMap
        );

        //Not found function
        //[DllImport("KernelBase.dll", SetLastError = true)]
        //public static extern IntPtr MapViewOfFile2(
        //    IntPtr fileMapping,
        //    IntPtr processHandle,
        //    UInt64 Offset,
        //    IntPtr baseAddress,
        //    uint size,
        //    FileMapAccessType allocationType,
        //    MEM_PAGE pageProtection
        //);

        [DllImport("KernelBase.dll", SetLastError = true)]
        public static extern IntPtr MapViewOfFile3(
           IntPtr hFileMappingObject,
           IntPtr process,
           IntPtr baseAddress,
           ulong offset,
           uint dwNumberOfBytesToMap,
           FileMapAccessType allocationType,
           MEM_PAGE dwDesiredAccess,
           IntPtr extendedParameters,
           ulong parameterCount
        );

        [DllImport("kernel32.dll")]
        public static extern IntPtr MapViewOfFileEx(
            IntPtr hFileMappingObject,
            FileMapAccessType dwDesiredAccess,
            ulong dwFileOffsetHigh,
            ulong dwFileOffsetLow,
            uint dwNumberOfBytesToMap,
            IntPtr lpBaseAddress
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool UnmapViewOfFile(
                IntPtr lpBaseAddress
        );
        */

        //[03]
        //SHELLCODE LOCATION
        //GlobalAlloc               GHND
        //GlobalLock
        //VirtualProtect            PAGE_EXECUTE_READWRITE
        //COPY MEMORY
        //EXECUTION FUNCTION
        //GlobalUnlock
        //GlobalFree
        /*
        [Flags]
        public enum GMEM : uint
        {
            FIXED = 0x0000,
            MOVEABLE = 0x0002,
            NOCOMPACT = 0x0010,
            NODISCARD = 0x0020,
            ZEROINIT = 0x0040,
            MODIFY = 0x0080,
            DISCARDABLE = 0x0100,
            NOT_BANKED = 0x1000,
            SHARE = 0x2000,
            DDESHARE = 0x2000,
            NOTIFY = 0x4000,
            LOWER = NOT_BANKED,
            DISCARDED = 0x4000,
            LOCKCOUNT = 0x00ff,
            INVALID_HANDLE = 0x8000,

            GHND = MOVEABLE | ZEROINIT,
            GPTR = FIXED | ZEROINIT,
        }

        public enum MEM_PAGE : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
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

        [DllImport("kernel32.dll")]
        static extern IntPtr GlobalAlloc(
            GMEM uFlags,
            uint dwBytes
        );

        [DllImport("kernel32.dll")]
        static extern IntPtr GlobalLock(
            IntPtr hMem
        );

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GlobalUnlock(
            IntPtr hMem
        );

        [DllImport("kernel32.dll")]
        static extern IntPtr GlobalFree(
            IntPtr hMem
        );

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(
            IntPtr lpAddress,
            int dwSize,
            MEM_PAGE flNewProtect,
            out uint lpflOldProtect
        );
        */

        //[04]
        //SHELLCODE LOCATION
        //GlobalAlloc               GPTR
        //VirtualProtect            PAGE_EXECUTE_READWRITE
        //COPY MEMORY
        //EXECUTION FUNCTION
        //GlobalFree
        /*
        [Flags]
        public enum GMEM : uint
        {
            FIXED = 0x0000,
            MOVEABLE = 0x0002,
            NOCOMPACT = 0x0010,
            NODISCARD = 0x0020,
            ZEROINIT = 0x0040,
            MODIFY = 0x0080,
            DISCARDABLE = 0x0100,
            NOT_BANKED = 0x1000,
            SHARE = 0x2000,
            DDESHARE = 0x2000,
            NOTIFY = 0x4000,
            LOWER = NOT_BANKED,
            DISCARDED = 0x4000,
            LOCKCOUNT = 0x00ff,
            INVALID_HANDLE = 0x8000,

            GHND = MOVEABLE | ZEROINIT,
            GPTR = FIXED | ZEROINIT,
        }

        public enum MEM_PAGE : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
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

        [DllImport("kernel32.dll")]
        static extern IntPtr GlobalAlloc(
            GMEM uFlags,
            uint dwBytes
        );

        [DllImport("kernel32.dll")]
        static extern IntPtr GlobalFree(
            IntPtr hMem
        );

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(
            IntPtr lpAddress,
            int dwSize,
            MEM_PAGE flNewProtect,
            out uint lpflOldProtect
        );
        */

        //[05]
        //SHELLCODE LOCATION
        //HeapCreate
        //HeapAlloc
        //COPY MEMORY
        //EXECUTION FUNCTION
        //HeapFree
        //HeapDestroy
        /*
        [Flags]
        public enum HeapFlags : uint
        {
            NoSerialize = 0x00000001,
            Growable = 0x00000002,
            GenerateExceptions = 0x00000004,
            ZeroMemory = 0x00000008,
            ReallocInPlaceOnly = 0x00000010,
            TailCheckingEnabled = 0x00000020,
            FreeCheckingEnabled = 0x00000040,
            DisableCoalesceOnFree = 0x00000080,

            CreateAlign16 = 0x00010000,
            CreateEnableTracing = 0x00020000,
            CreateEnableExecute = 0x00040000,

            SettableUserValue = 0x00000100,
            SettableUserFlag1 = 0x00000200,
            SettableUserFlag2 = 0x00000400,
            SettableUserFlag3 = 0x00000800,
            SettableUserFlags = 0x00000e00,

            Class0 = 0x00000000, // Process heap
            Class1 = 0x00001000, // Private heap
            Class2 = 0x00002000, // Kernel heap
            Class3 = 0x00003000, // GDI heap
            Class4 = 0x00004000, // User heap
            Class5 = 0x00005000, // Console heap
            Class6 = 0x00006000, // User desktop heap
            Class7 = 0x00007000, // CSRSS shared heap
            Class8 = 0x00008000, // CSR port heap
            ClassMask = 0x0000f000
        }

        [Flags]
        public enum dwFlags
        {
            HEAP_GENERATE_EXCEPTIONS = 0x00040000,
            HEAP_NO_SERIALIZE = 0x00000001,
            HEAP_ZERO_MEMORY = 0x00000008
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr HeapCreate(
            HeapFlags flOptions,
            uint dwInitialSize,
            uint dwMaximumSize
        );

        [DllImport("kernel32.dll", SetLastError = false)]
        static extern IntPtr HeapAlloc(
            IntPtr hHeap,
            dwFlags dwFlags,
            uint dwBytes
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool HeapFree(
            IntPtr hHeap,
            uint dwFlags,
            IntPtr lpMem
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool HeapDestroy(
            IntPtr hHeap
        );
        */

        //[06]
        //SHELLCODE LOCATION
        //NtAllocateVirtualMemory   PAGE_EXECUTE_READWRITE
        //COPY MEMORY
        //EXECUTION FUNCTION
        //NtFreeVirtualMemory
        /*
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern IntPtr NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UInt32 ZeroBits,
            ref uint RegionSize,
            MEM_COMMIT AllocationType,
            MEM_PAGE Protect
        );

        [DllImport(dllName: "ntdll.dll", SetLastError = true)]
        static extern int NtFreeVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref uint regionSize,
            MEM_COMMIT freeType
        );
        */

        //[07]
        //SHELLCODE LOCATION
        //NtCreateSection           PAGE_EXECUTE_READWRITE
        //NtMapViewOfSection        PAGE_EXECUTE_READWRITE
        //COPY MEMORY
        //EXECUTION FUNCTION
        //NtUnmapViewOfSection
        //NtClose
        /*
        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        IntPtr SectionHandle = IntPtr.Zero;
        private static uint SEC_COMMIT = 0x08000000;
        private static uint SECTION_MAP_WRITE = 0x0002;
        private static uint SECTION_MAP_READ = 0x0004;
        private static uint SECTION_MAP_EXECUTE = 0x0008;
        private static uint SECTION_ALL_ACCESS = SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE;
        
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtCreateSection(
            ref IntPtr SectionHandle,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            ref UInt64 MaximumSize,
            MEM_PAGE SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtMapViewOfSection(
            IntPtr SectionHandle, 
            IntPtr ProcessHandle, 
            ref IntPtr BaseAddress, 
            UIntPtr ZeroBits, 
            UIntPtr CommitSize, 
            ref UInt64 SectionOffset, 
            ref UInt64 ViewSize, 
            uint InheritDisposition, 
            UInt32 AllocationType,
            MEM_PAGE Win32Protect
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr
        );

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(
            IntPtr hObject
        );
        */

        //[08]
        //SHELLCODE LOCATION
        //NtCreateSectionEx         PAGE_EXECUTE_READWRITE
        //NtMapViewOfSection        PAGE_EXECUTE_READWRITE
        // NEED to FIND way NtMapViewOfSectionEx      
        //COPY MEMORY
        //EXECUTION FUNCTION
        //NtUnmapViewOfSectionEx
        //NtCloseEX
        /*
        public enum MEM_PAGE : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
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

        private static uint SEC_COMMIT = 0x08000000;
        private static uint SECTION_MAP_WRITE = 0x0002;
        private static uint SECTION_MAP_READ = 0x0004;
        private static uint SECTION_MAP_EXECUTE = 0x0008;
        private static uint SEC_IMAGE = 0x1000000;
        private static uint SECTION_ALL_ACCESS = SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE;
        public enum MEM_EXTENDED_PARAMETER_TYPE
        {
            MemExtendedParameterInvalidType = 0,
            MemExtendedParameterAddressRequirements,
            MemExtendedParameterNumaNode,
            MemExtendedParameterPartitionHandle,
            MemExtendedParameterMax
        }

        public struct MEM_EXTENDED_PARAMETER
        {
            public MEM_EXTENDED_PARAMETER_TYPE Type;
            public UInt64 ULong64;
            public IntPtr Pointer;
            public int Size;
            public IntPtr Handle;
            public uint ULong;
        }

        public enum SectionInherit
        {
            ViewShare = 1,
            ViewUnmap = 2
        }

        [Flags]
        public enum AllocationType
        {
            None = 0,
            Commit = 0x00001000,
            Reserve = 0x00002000,
            ReplacePlaceholder = 0x00004000,
            Reset = 0x00080000,
            ResetUndo = 0x1000000,
            LargePages = 0x20000000,
            Physical = 0x00400000,
            TopDown = 0x00100000,
            WriteWatch = 0x00200000,
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr NtCreateSectionEx(
            ref IntPtr SectionHandle,
            UInt32 DesiredAccess,
            [In] IntPtr ObjectAttributes,
            ref UInt64 ViewSize,
            MEM_PAGE SectionPageProtection, 
            uint AllocationAttributes,
            IntPtr FileHandle,
            MEM_EXTENDED_PARAMETER ExtendedParameters, 
            int ExtendedParameterCount
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UIntPtr ZeroBits,
            UIntPtr CommitSize,
            ref UInt64 SectionOffset,
            ref UInt64 ViewSize,
            uint InheritDisposition,
            UInt32 AllocationType,
            MEM_PAGE Win32Protect
        );

        //NEED to FIND way
        //[DllImport("ntdll.dll")]
        //public static extern IntPtr NtMapViewOfSectionEx(
        //    IntPtr SectionHandle,
        //    IntPtr ProcessHandle,
        //    ref IntPtr BaseAddress,
        //    IntPtr ZeroBits,
        //    uint CommitSize,
        //    [In, Out] long SectionOffset,
        //    ref uint ViewSize,
        //    SectionInherit InheritDisposition,
        //    AllocationType AllocationType,
        //    MEM_PAGE Win32Protect,
        //    MEM_EXTENDED_PARAMETER ExtendedParameters,
        //    int ExtendedParameterCount
        //);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern IntPtr NtUnmapViewOfSectionEx(
            IntPtr hProc,
            IntPtr baseAddr
        );

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtCloseEx(
            IntPtr hObject
        );
        */

        //[09]
        //SHELLCODE LOCATION
        //RtlCreateHeap
        //RtlAllocateHeap
        //COPY MEMORY
        //EXECUTION FUNCTION
        //RtlFreeHeap
        //RtlDestroyHeap
        /*
        [Flags]
        public enum HeapFlags : uint
        {
            NoSerialize = 0x00000001,
            Growable = 0x00000002,
            GenerateExceptions = 0x00000004,
            ZeroMemory = 0x00000008,
            ReallocInPlaceOnly = 0x00000010,
            TailCheckingEnabled = 0x00000020,
            FreeCheckingEnabled = 0x00000040,
            DisableCoalesceOnFree = 0x00000080,

            CreateAlign16 = 0x00010000,
            CreateEnableTracing = 0x00020000,
            CreateEnableExecute = 0x00040000,

            SettableUserValue = 0x00000100,
            SettableUserFlag1 = 0x00000200,
            SettableUserFlag2 = 0x00000400,
            SettableUserFlag3 = 0x00000800,
            SettableUserFlags = 0x00000e00,

            Class0 = 0x00000000, // Process heap
            Class1 = 0x00001000, // Private heap
            Class2 = 0x00002000, // Kernel heap
            Class3 = 0x00003000, // GDI heap
            Class4 = 0x00004000, // User heap
            Class5 = 0x00005000, // Console heap
            Class6 = 0x00006000, // User desktop heap
            Class7 = 0x00007000, // CSRSS shared heap
            Class8 = 0x00008000, // CSR port heap
            ClassMask = 0x0000f000
        }

        [Flags]
        public enum dwFlags
        {
            HEAP_GENERATE_EXCEPTIONS = 0x00040000,
            HEAP_NO_SERIALIZE = 0x00000001,
            HEAP_ZERO_MEMORY = 0x00000008
        }

        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlCreateHeap(
            [In] HeapFlags Flags,
            [In][Optional] IntPtr HeapBase,
            [In][Optional] IntPtr ReserveSize,
            [In][Optional] IntPtr CommitSize,
            [In][Optional] IntPtr Lock,
            [In][Optional] IntPtr Parameters
        );

        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlAllocateHeap(
            [In] IntPtr HeapHandle,
            [In] dwFlags Flags,
            [In] uint Size
        );

        [DllImport("ntdll.dll")]
        [return: MarshalAs(UnmanagedType.U1)]
        public static extern bool RtlFreeHeap(
            [In] IntPtr HeapHandle,
            [In] HeapFlags Flags,
            [In] IntPtr BaseAddress
        );

        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlDestroyHeap(
            [In] IntPtr HeapHandle
        );
        */

        //[0A]
        //SHELLCODE LOCATION
        //VirtualAlloc
        //COPY MEMORY
        //EXECUTION FUNCTION
        //VirtualFree
        /*
        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress, 
            uint dwSize,
            MEM_COMMIT flAllocationType,
            MEM_PAGE flProtect
        );

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool VirtualFree(
            IntPtr lpAddress,
            uint dwSize,
            MEM_COMMIT dwFreeType
        );
        */

        //[0B]
        //SHELLCODE LOCATION
        //VirtualAlloc2
        //COPY MEMORY
        //EXECUTION FUNCTION
        //VirtualFree
        /*
        [DllImport("KernelBase.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc2(
            IntPtr process,
            IntPtr lpAddress,
            uint dwSize,
            MEM_COMMIT flAllocationType,
            MEM_PAGE flProtect,
            IntPtr extendedParameters,
            ulong parameterCount
        );

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool VirtualFree(
            IntPtr lpAddress,
            uint dwSize,
            MEM_COMMIT dwFreeType
        );
        */

        //[0C]
        //SHELLCODE LOCATION
        //VirtualAllocEx
        //COPY MEMORY
        //EXECUTION FUNCTION
        //VirtualFreeEx
        /*
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            MEM_COMMIT flAllocationType,
            MEM_PAGE flProtect
        );

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool VirtualFreeEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            MEM_COMMIT dwFreeType
        );
        */

        //[0D]
        //SHELLCODE LOCATION
        //LocalAlloc
        //VirtualProtect            PAGE_EXECUTE_READWRITE
        //COPY MEMORY
        //EXECUTION FUNCTION
        //LocalFree
        /*
        [Flags]
        public enum LocalMemoryFlags
        {
            LMEM_FIXED = 0x0000,
            LMEM_MOVEABLE = 0x0002,
            LMEM_NOCOMPACT = 0x0010,
            LMEM_NODISCARD = 0x0020,
            LMEM_ZEROINIT = 0x0040,
            LMEM_MODIFY = 0x0080,
            LMEM_DISCARDABLE = 0x0F00,
            LMEM_VALID_FLAGS = 0x0F72,
            LMEM_INVALID_HANDLE = 0x8000,
            LHND = (LMEM_MOVEABLE | LMEM_ZEROINIT),
            LPTR = (LMEM_FIXED | LMEM_ZEROINIT),
            NONZEROLHND = (LMEM_MOVEABLE),
            NONZEROLPTR = (LMEM_FIXED)
        }

        public enum MEM_PAGE : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
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

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalAlloc(
            LocalMemoryFlags uFlags,
            UIntPtr uBytes
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(
            IntPtr hMem
        );

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(
           IntPtr lpAddress,
           int dwSize,
           MEM_PAGE flNewProtect,
           out uint lpflOldProtect
        );
        */

        //[0E]
        //SHELLCODE LOCATION
        //SHAlloc
        //VirtualProtect            PAGE_EXECUTE_READWRITE
        //COPY MEMORY
        //EXECUTION FUNCTION
        //SHFree
        /*
        public enum MEM_PAGE : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
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
        
        [DllImport("shell32.dll", SetLastError = false, ExactSpelling = true)]
        public static extern IntPtr SHAlloc(
            uint cb
        );

        [DllImport("shell32.dll", SetLastError = false, ExactSpelling = true)]
        public static extern void SHFree(
            IntPtr hNameMappings
        );

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(
           IntPtr lpAddress,
           int dwSize,
           MEM_PAGE flNewProtect,
           out uint lpflOldProtect
        );
        */

        //[0F]
        //SHELLCODE LOCATION
        //VirtualAllocExNuma
        //COPY MEMORY
        //EXECUTION FUNCTION
        //VirtualFreeEx
        /*
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(
            IntPtr hProcess, 
            IntPtr lpAddress,
            uint dwSize,
            MEM_COMMIT flAllocationType,
            MEM_PAGE flProtect, 
            UInt32 nndPreferred
        );

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool VirtualFreeEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            MEM_COMMIT dwFreeType
        );
        */

        //[10]
        //SHELLCODE LOCATION
        //GCHandle.Alloc
        //.AddrOfPinnedObject();
        //VirtualProtect            PAGE_EXECUTE_READWRITE
        //COPY MEMORY
        //EXECUTION FUNCTION
        //.Free();
        /*
        public enum MEM_PAGE : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
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

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(
          IntPtr lpAddress,
          int dwSize,
          MEM_PAGE flNewProtect,
          out uint lpflOldProtect
        );
        */

        //[11]
        //SHELLCODE LOCATION
        //Marshal.AllocCoTaskMem
        //VirtualProtect            PAGE_EXECUTE_READWRITE
        //COPY MEMORY
        //EXECUTION FUNCTION
        //Marshal.FreeCoTaskMem
        /*
        public enum MEM_PAGE : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
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

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(
          IntPtr lpAddress,
          int dwSize,
          MEM_PAGE flNewProtect,
          out uint lpflOldProtect
        );
        */

        //[12]
        //SHELLCODE LOCATION
        //AllocHGlobal
        //VirtualProtect            PAGE_EXECUTE_READWRITE
        //COPY MEMORY
        //EXECUTION FUNCTION
        //FreeHGlobal
        /*
        public enum MEM_PAGE : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
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

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(
          IntPtr lpAddress,
          int dwSize,
          MEM_PAGE flNewProtect,
          out uint lpflOldProtect
        );
        */

        static void Main(string[] args)
        {
            //SHELLCODE LOCATION

            //ALLOCATION MEMORY
            //[00]
            /*
            IntPtr hMem = AllocADsMem(
                buf.Length
            );
           
            uint lpflOldProtect = 0;
            bool status = VirtualProtect(
                hMem,
                buf.Length,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                out lpflOldProtect
            );
            */

            //[01]
            /*
            IntPtr hMem = CoTaskMemAlloc(
                buf.Length
            );
            
            uint lpflOldProtect = 0;
            bool status = VirtualProtect(
                hMem,
                buf.Length,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                out lpflOldProtect
            );
            */

            //[02]
            /*
            IntPtr mapfile = CreateFileMapping(
                INVALID_HANDLE_VALUE,
                IntPtr.Zero,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                0,
                (uint)buf.Length,
                null
            );

            IntPtr mapfile = CreateFileMappingA(
                INVALID_HANDLE_VALUE,
                IntPtr.Zero,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                0,
                (uint)buf.Length,
                null
            );
            
            IntPtr mapfile = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                IntPtr.Zero,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                0,
                (uint)buf.Length,
                null
            );
            
            IntPtr hMem = MapViewOfFile(
                mapfile,
                FileMapAccessType.Write|FileMapAccessType.Execute,
                0,
                0,
                (uint)buf.Length
            );
            

            //Not found function
            //IntPtr hProcess = Process.GetCurrentProcess().Handle;
            //ulong offset = 0;
            //uint size = (uint)buf.Length;
            //IntPtr hMem = MapViewOfFile2(
            //    mapfile,
            //    hProcess,
            //    offset,
            //    IntPtr.Zero,
            //    (uint)size,
            //    FileMapAccessType.Write | FileMapAccessType.Execute,
            //    MEM_PAGE.PAGE_EXECUTE_READWRITE
            //);

            
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            ulong offset = 0;
            uint size = (uint)buf.Length;
            IntPtr hMem = MapViewOfFile3(
                mapfile,
                hProcess,
                IntPtr.Zero,
                offset,
                (uint)size,
                0,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                IntPtr.Zero,
                0
            );

            ulong offset = 0;
            uint size = (uint)buf.Length;
            IntPtr hMem = MapViewOfFileEx(
                mapfile,
                FileMapAccessType.Write | FileMapAccessType.Execute,
                offset,
                offset,
                size,
                IntPtr.Zero
            );
            */

            //[03]
            /*
            IntPtr runtime = GlobalAlloc(
                GMEM.GHND,
                (uint)buf.Length
            );
            IntPtr hMem = GlobalLock(
                runtime
            );

            uint lpflOldProtect = 0;
            bool status = VirtualProtect(
                hMem,
                buf.Length,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                out lpflOldProtect
            );
            */

            //[04]
            /*
            IntPtr hMem = GlobalAlloc(
                GMEM.GPTR,
                (uint)buf.Length
            );

            uint lpflOldProtect = 0;
            bool status = VirtualProtect(
                hMem,
                buf.Length,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                out lpflOldProtect
            );
            */

            //[05]
            /*
            uint PAGE_SIZE = 4096;
            IntPtr heap = HeapCreate(
                HeapFlags.CreateEnableExecute,
                10 * PAGE_SIZE,
                100 * PAGE_SIZE
            );
            IntPtr hMem = HeapAlloc(
                heap,
                dwFlags.HEAP_ZERO_MEMORY,
                (uint)buf.Length
            );
            */

            //[06]
            /*
            IntPtr hMem = IntPtr.Zero;
            uint regionSize = (uint)buf.Length;
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            NtAllocateVirtualMemory(
                hProcess,
                ref hMem,
                0,
                ref regionSize,
                MEM_COMMIT.MEM_COMMIT | MEM_COMMIT.MEM_RESERVE,
                MEM_PAGE.PAGE_EXECUTE_READWRITE
            );
            */

            //[07]
            /*
            IntPtr hSectionHandle = IntPtr.Zero;
            UInt64 size = (UInt64)buf.Length;

            NtCreateSection(
                ref hSectionHandle,
                SECTION_ALL_ACCESS,
                IntPtr.Zero,
                ref size,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                SEC_COMMIT,
                IntPtr.Zero
            );

            IntPtr hMem = IntPtr.Zero;
            ulong offset = 0;
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            const UInt32 ViewUnmap = 0x2;
            size = 0;
            NtMapViewOfSection(
                hSectionHandle,
                hProcess,
                ref hMem,
                UIntPtr.Zero,
                UIntPtr.Zero,
                ref offset,
                ref size,
                ViewUnmap,
                0,
                MEM_PAGE.PAGE_EXECUTE_READWRITE
            );
            */

            //[08]
            /*
            IntPtr hSectionHandle = IntPtr.Zero;
            UInt64 size = (UInt64)buf.Length;
            MEM_EXTENDED_PARAMETER mem = new MEM_EXTENDED_PARAMETER();
            NtCreateSectionEx(
                ref hSectionHandle, 
                SECTION_ALL_ACCESS,
                IntPtr.Zero,
                ref size, 
                MEM_PAGE.PAGE_EXECUTE_READWRITE, 
                SEC_COMMIT,
                IntPtr.Zero,
                mem,
                0
            );

            IntPtr hMem = IntPtr.Zero;
            ulong offset = 0;
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            const UInt32 ViewUnmap = 0x2;
            size = 0;
            NtMapViewOfSection(
                hSectionHandle,
                hProcess,
                ref hMem,
                UIntPtr.Zero,
                UIntPtr.Zero,
                ref offset,
                ref size,
                ViewUnmap,
                0,
                MEM_PAGE.PAGE_EXECUTE_READWRITE
            );

            //NEED to FIND way
            //MEM_EXTENDED_PARAMETER memExt = new MEM_EXTENDED_PARAMETER();
            //IntPtr hMem = IntPtr.Zero;
            //long offset = 0;
            //IntPtr hProcess = Process.GetCurrentProcess().Handle;
            //uint ViewUnmap = 0;
            //uint ViewSize = 0;
            //IntPtr stastus = NtMapViewOfSectionEx(
            //    hSectionHandle,
            //    hProcess,
            //    ref hMem,
            //    IntPtr.Zero,
            //    (uint)buf.Length,
            //    offset,
            //    ref ViewSize,
            //    SectionInherit.ViewShare,
            //    AllocationType.None,
            //    MEM_PAGE.PAGE_EXECUTE_READWRITE,
            //    mem,
            //    0
            //);
            */

            //[09]
            /*
            IntPtr heap = RtlCreateHeap(
                HeapFlags.CreateEnableExecute,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero
            );

            IntPtr hMem = RtlAllocateHeap(
                heap, 
                dwFlags.HEAP_ZERO_MEMORY, 
                (uint)buf.Length
            );
            */

            //[0A]
            /*
            IntPtr hMem = VirtualAlloc(
                IntPtr.Zero,
                (uint)buf.Length,
                MEM_COMMIT.MEM_COMMIT | MEM_COMMIT.MEM_RESERVE,
                MEM_PAGE.PAGE_EXECUTE_READWRITE
            );
            */

            //[0B]
            /*
            IntPtr hMem = VirtualAlloc2(
                IntPtr.Zero,
                IntPtr.Zero,
                (uint)buf.Length,
                MEM_COMMIT.MEM_COMMIT | MEM_COMMIT.MEM_RESERVE,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                IntPtr.Zero,
                0
            );
            */

            //[0C]
            /*
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            IntPtr hMem = VirtualAllocEx(
                hProcess,
                IntPtr.Zero,
                (uint)buf.Length,
                MEM_COMMIT.MEM_COMMIT | MEM_COMMIT.MEM_RESERVE,
                MEM_PAGE.PAGE_EXECUTE_READWRITE
            );
            */

            //[0D]
            /*
            IntPtr hMem = LocalAlloc(
                LocalMemoryFlags.LHND,
                new UIntPtr((uint)buf.Length)
            );

            uint lpflOldProtect = 0;
            bool status = VirtualProtect(
                hMem,
                buf.Length,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                out lpflOldProtect
            );
            */

            //[0E]
            /*
            IntPtr hMem = SHAlloc(
                (uint)buf.Length
            );
            uint lpflOldProtect = 0;
            bool status = VirtualProtect(
                hMem,
                buf.Length,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                out lpflOldProtect
            );
            */

            //[0F]
            /*
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            IntPtr hMem = VirtualAllocExNuma(
                hProcess,
                IntPtr.Zero,
                (uint)buf.Length,
                MEM_COMMIT.MEM_COMMIT | MEM_COMMIT.MEM_RESERVE,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                0
            );
            */

            //[10]
            /*
            GCHandle hMem2 = GCHandle.Alloc(
                buf,
                GCHandleType.Pinned
            );
            IntPtr hMem = hMem2.AddrOfPinnedObject();
           
            uint lpflOldProtect = 0;
            bool status = VirtualProtect(
                hMem,
                buf.Length,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                out lpflOldProtect
            );
            */

            //[11]
            /*
            IntPtr hMem = Marshal.AllocCoTaskMem(
                buf.Length
            );

            uint lpflOldProtect = 0;
            bool status = VirtualProtect(
                hMem,
                buf.Length,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                out lpflOldProtect
            );
            */

            //[12]
            /*
            var hMem = Marshal.AllocHGlobal(buf.Length);

            uint lpflOldProtect = 0;
            bool status = VirtualProtect(
                hMem,
                buf.Length,
                MEM_PAGE.PAGE_EXECUTE_READWRITE,
                out lpflOldProtect
            );
            */

            //WRITE MEMORY

            //EXECUTION FUNCTION

            //FREE MEMORY
            //[00]
            /*
            FreeADsMem(
                hMem
            );
            */

            //[01]
            /*
            CoTaskMemFree(
                hMem
            );
            */

            //[02]
            /*
            UnmapViewOfFile(
                hMem
            );
            */

            //[03]
            /*
            GlobalUnlock(
                runtime
            );
            GlobalFree(
                runtime
            );
            */

            //[04]
            /*
            GlobalFree(
                hMem
            );
            */

            //[05]
            /*
            HeapFree(
                heap,
                0,
                hMem
            );
            HeapDestroy(
                heap
            );
            */

            //[06]
            /*
            NtFreeVirtualMemory(
                hProcess,
                ref hMem,
                ref regionSize,
                MEM_COMMIT.MEM_RELEASE
            );
            */

            //[07]
            /*
            NtUnmapViewOfSection(
                hProcess,
                hMem
            );
            NtClose(
                hSectionHandle
            );
            */

            //[08]
            /*
            NtUnmapViewOfSectionEx(
                hProcess,
                hMem
            );
            NtCloseEx(
                hSectionHandle
            );
            */

            //[09]
            /*
            RtlFreeHeap(
                heap,
                0,
                hMem
            );
            RtlDestroyHeap(
                heap
            );
            */

            //[0A]
            /*
            VirtualFree(
                hMem,
                (uint)buf.Length, 
                MEM_COMMIT.MEM_RELEASE
            );
            */

            //[0B]
            /*
            VirtualFree(
                hMem,
                (uint)buf.Length, 
                MEM_COMMIT.MEM_RELEASE
            );
            */

            //[0C]
            /*
            VirtualFreeEx(
                hProcess,
                hMem,
                (uint)buf.Length,
                MEM_COMMIT.MEM_RELEASE
            );
            */

            //[0D]
            /*
            LocalFree(
                hMem
            );
            */

            //[0E]
            /*
            SHFree(
                hMem
            );
            */

            //[0F]
            /*
            VirtualFreeEx(
                hProcess,
                hMem,
                (uint)buf.Length,
                MEM_COMMIT.MEM_RELEASE
            );
            */

            //[10]
            /*
            hMem2.Free();
            */

            //[11]
            /*
            Marshal.FreeCoTaskMem(
                hMem
            );
            */

            //[12]
            /*
            Marshal.FreeHGlobal(hMem);
            */
        }
    }
}
