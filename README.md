# Shellcode

## Shellcode
```
[00] NASM x86_64
```

## Shellcode Location
```
[00]	Local Varible
[01]	Global Variable
[02]	Resource File
[03]	File From Disk		!NOT LOTD!
[04]	Network

```

## Memory Allocation Functions

```
[00]
	AllocADsMem
	VirtualProtect			PAGE_EXECUTE_READWRITE
	COPY MEMORY
	EXECUTION FUNCTION
	FreeADsMem
[01]
	CoTaskMemAlloc
	VirtualProtect			PAGE_EXECUTE_READWRITE
	COPY MEMORY
	EXECUTION FUNCTION
	CoTaskMemFree
[02]
	CreateFileMapping 		PAGE_EXECUTE_READWRITE
		OR  CreateFileMappingA
		OR  CreateFileMappingW
	MapViewOfFile			Write|Execute
		OR  MapViewOfFile3
	 	OR  MapViewOfFileEx
		!NEED to FIND way MapViewOfFile2		Function not found!
	COPY MEMORY
	EXECUTION FUNCTION
	UnmapViewOfFile
[03]
	GlobalAlloc				GHND
	GlobalLock
	VirtualProtect			PAGE_EXECUTE_READWRITE
	COPY MEMORY
	EXECUTION FUNCTION
	GlobalUnlock
	GlobalFree
[04]
	GlobalAlloc 			GPTR
	VirtualProtec			PAGE_EXECUTE_READWRITE
	COPY MEMORY
	EXECUTION FUNCTION
	GlobalFree
[05]
	HeapCreate
	HeapAlloc
	COPY MEMORY
	EXECUTION FUNCTION
	HeapFree
	HeapDestroy
[06]
	NtAllocateVirtualMemory	PAGE_EXECUTE_READWRITE
	COPY MEMORY
	EXECUTION FUNCTION
	NtFreeVirtualMemory
[07]
	NtCreateSection			PAGE_EXECUTE_READWRITE
	NtMapViewOfSection		PAGE_EXECUTE_READWRITE
	COPY MEMORY
	EXECUTION FUNCTION
	NtUnmapViewOfSection
	NtClose
[08]
	NtCreateSectionEx		PAGE_EXECUTE_READWRITE
	NtMapViewOfSection		PAGE_EXECUTE_READWRITE
		!NEED to FIND way NtMapViewOfSectionEx		C0000005 (STATUS_ACCESS_VIOLATION)!
	COPY MEMORY
	EXECUTION FUNCTION
	NtUnmapViewOfSectionEx
	NtCloseEX
[09]
	RtlCreateHeap
	RtlAllocateHeap
	COPY MEMORY
	EXECUTION FUNCTION
	RtlFreeHeap
	RtlDestroyHeap
[0A]
	VirtualAlloc
	COPY MEMORY
	EXECUTION FUNCTION
	VirtualFree
[0B]
	VirtualAlloc2
	COPY MEMORY
	EXECUTION FUNCTION
	VirtualFree
[0C]
	VirtualAllocEx
	COPY MEMORY
	EXECUTION FUNCTION
	VirtualFreeEx
[0D]
	LocalAlloc
	VirtualProtect			PAGE_EXECUTE_READWRITE
	COPY MEMORY
	EXECUTION FUNCTION
	LocalFree
[0E]
	SHAlloc
	VirtualProtect			PAGE_EXECUTE_READWRITE
	COPY MEMORY
	EXECUTION FUNCTION
	SHFree
[0F]
	VirtualAllocExNuma
	COPY MEMORY
	EXECUTION FUNCTION
	VirtualFreeEx
[10]
	GCHandle.Alloc
	.AddrOfPinnedObject();
	VirtualProtect			PAGE_EXECUTE_READWRITE
	COPY MEMORY
	EXECUTION FUNCTION
	.Free();
```
 
## Code Execution Functions

```
[00]	acmDriverEnum
[01]	acmFormatTagEnum
[02]	BindImageEx
[03]	CallWindowProc (CallWindowProcA, CallWindowProcW)
[04]	CDefFolderMenu_Create2
[05]	CertCreateContext
[06]	CertEnumPhysicalStore
[07]	CertEnumSystemStore
[08]	CertEnumSystemStoreLocation
[09]	ChooseColor
[0A]	ChooseFont
[0B]	ClusWorkerCreate
[0C]	CopyFile2
[0D]	CopyFileEx
[0E]	CreateDialogIndirectParam (CreateDialogIndirectParamA, CreateDialogIndirectParamW)
[0F]	CreateThread
[10]	CreateThreadpoolTimer
[11]	CreateThreadpoolWait
[12]	CreateThreadpoolWork
[13]	CreateTimerQueueTimer
[14]	CryptEnumOIDFunction
[15]	CryptEnumOIDInfo
[16]	DbgHelpCreateUserDump (DbgHelpCreateUserDumpW)
[17]	DdeInitialize (DdeInitializeA, DdeInitializeW)
[18]	DialogBoxIndirectParam (DialogBoxIndirectParamA, DialogBoxIndirectParamW)
[19]	DirectDrawEnumerateEx (DirectDrawEnumerateExA, DirectDrawEnumerateExW)
[1A]	DirectSoundCaptureEnumerate (DirectSoundCaptureEnumerateA, DirectSoundCaptureEnumerateW)
[1B]	DirectSoundEnumerate (DirectSoundEnumerateA, DirectSoundEnumerateW)
[1C]	DnsStartMulticastQuery
[1D]	DrawState (DrawStateA, DrawStateW)
[1E]	DSA_EnumCallback
[1F]	EnumCalendarInfo (EnumCalendarInfoA, EnumCalendarInfoW)
[20]	EnumCalendarInfoEx
[21]	EnumChildWindows
[22]	EnumDateFormats (EnumDateFormatsA, EnumDateFormatsW)
[23]	EnumDateFormatsEx
[24]	EnumDateFormatsExEx
[25]	EnumDesktops (EnumDesktopsA, EnumDesktopsW)
[26]	EnumDesktopWindows
[27]	EnumDirTree (EnumDirTreeA, EnumDirTreeW)
[28]	EnumDisplayMonitors
[29]	EnumerateLoadedModules (EnumerateLoadedModules64, EnumerateLoadedModulesW64)
[2A]	EnumerateLoadedModulesEx (EnumerateLoadedModulesExW)
[2B]	EnumLanguageGroupLocales (EnumLanguageGroupLocalesA, EnumLanguageGroupLocalesW)
[2C]	EnumObjects
[2D]	EnumPageFiles (EnumPageFilesA, EnumPageFilesW)
[2E]	EnumProps
[2F]	EnumPropsEx (EnumPropsExA, EnumPropsExW)
[30]	EnumPwrSchemes
[31]	EnumResourceTypes (EnumResourceTypesA, EnumResourceTypesW)
[32]	EnumResourceTypesEx (EnumResourceTypesExA, EnumResourceTypesExW)
[33]	EnumSystemCodePages (EnumSystemCodePagesA, EnumSystemCodePagesW
[34]	EnumSystemGeoID
[35]	EnumSystemLanguageGroups (EnumSystemLanguageGroupsA, EnumSystemLanguageGroupsW)
[36]	EnumSystemLocales (EnumSystemLocalesA, EnumSystemLocalesW)
[37]	EnumSystemLocalesEx
[38]	EnumThreadWindows
[39]	EnumTimeFormats (EnumTimeFormatsA, EnumTimeFormatsW)
[3A]	EnumTimeFormatsEx
[3B]	EnumUILanguages (EnumUILanguagesA, EnumUILanguagesW)
[3C]	EnumWindows
[3D]	EnumWindowStations (EnumWindowStationsA, EnumWindowStationsW)
[3E]	EvtSubscribe_CVEEventWrite
[3F]	FCICreate
[40]	FindText
[41]	FlsAlloc
[42]	GetOpenFileName
[43]	GetSaveFileName
[44]	GrayString (GrayStringA, GrayStringW)
[45]	ImageGetDigestStream
[46]	ImmEnumInputContext
[47]	InitOnceExecuteOnce
[48]	InternetSetStatusCallback
[49]	LdrEnumerateLoadedModules
[4A]	LineDDA
[4B]	MFAddPeriodicCallback
[4C]	MiniDumpWriteDump
[4D]	NotifyIpInterfaceChange
[4E]	NotifyNetworkConnectivityHintChange
[4F]	NotifyRouteChange2
[50]	NotifyTeredoPortChange
[51]	NotifyUnicastIpAddressChange
[52]	NtTestAlert
[53]	OleUIBusy
[54]	PerfStartProviderEx
[55]	PowerRegisterForEffectivePowerModeNotifications
[56]	PrintDlg
[57]	ReadFileEx
[58]	RegisterApplicationRecoveryCallback
[59]	RegisterWaitChainCOMCallback
[5A]	RegisterWaitForSingleObject
[5B]	ReplaceText
[5C]	RoInspectCapturedStackBackTrace
[5D]	RoInspectThreadErrorInfo
[5E]	SendMessageCallback (SendMessageCallbackA, SendMessageCallbackW)
[5F]	SetTimer
[60]	SetupCommitFileQueue (SetupCommitFileQueueA, SetupCommitFileQueueW)
[61]	SetupInstallFile
[62]	SetupIterateCabinet
[63]	SetWaitableTimer
[64]	SHBrowseForFolder
[65]	SHCreateThread
[66]	SHCreateThreadWithHandle
[67]	StackWalk (StackWalk64)
[68]	SwitchToFiber
[69]	SymEnumProcesses
[6A]	SymFindFileInPath
[6B]	SymRegisterCallback
[6C]	TrySubmitThreadpoolCallback
[6D]	VerifierEnumResource
[6E]	WindowsInspectString
[6F]	WinHttpSetStatusCallback
[70]	WriteEncryptedFileRaw
[71]	WriteFileEx
[72]	PdhBrowseCounters
```

## FAILED Code Execution Functions
```
CryptDecodeMessage
CryptInstallOIDFunctionAddress
CryptVerifyMessageSignature
EnumResourceNames
EnumResourceNamesA
EnumResourceNamesW
GetApplicationRecoveryCallback
MFBeginRegisterWorkQueueWithMMCSS
SetWindowsHookEx
SetWindowsHookExA
SetWindowsHookExW
SetWinEventHook

acmFilterChoose
AddClusterNode
BluetoothRegisterForAuthentication
CertFindChainInStor
CMTranslateRGBsExt
CreateCluster
CreateDialogParam
CreateDialogParamA
CreateDialogParamW
CreatePrintAsyncNotifyChannel
DestroyCluster
DialogBoxParam
DialogBoxParamA
DialogBoxParamW
DNSServiceBrowse
EnumEnhMetaFile
EnumFontFamilies
EnumFontFamiliesEx
EnumFonts
EnumICMProfiles
EnumMetaFile
EnumResourceLanguages
EnumResourceLanguagesA
EnumResourceLanguagesEx
EnumResourceLanguagesExA
EnumResourceLanguagesExW
EnumResourceLanguagesW
EnumResourceNamesEx
EnumResourceNamesExA
EnumResourceNamesExW
LdrpCallInitRoutinу
MagSetWindowTransform
MappingRecognizeText
mciSetYieldProc
MessageBoxIndirect
MFBeginUnregisterWorkQueueWithMMCSS
MFPCreateMediaPlayer
midiInOpen
midiOutOpen
mixerOpen
mmioInstallIOProc
mmioInstallIOProcA
mmioInstallIOProcW
MQReceiveMessage
MQReceiveMessageByLookupId
NotifyStableUnicastIpAddressTable
NPAddConnection3
PageSetupDlg
PerfStartProvider
PlaExtractCabinet
ReadEncryptedFileRaw
RegisterForPrintAsyncNotifications
RegisterServiceCtrlHandlerEx
RegisterServiceCtrlHandlerExA
RegisterServiceCtrlHandlerExW
RegisterWaitForSingleObjectEx
RtlUserFiberStart
SetTimerQueueTimer
SetupDiRegisterDeviceInfo
SymEnumerateModules
SymEnumerateModules64
SymEnumerateSymbols
SymEnumerateSymbols64
SymEnumerateSymbolsW
SymEnumLines
SymEnumLinesW
SymEnumSourceFiles
SymEnumSourceLines
SymEnumSourceLinesW
SymEnumSymbols
SymEnumSymbolsA
SymEnumSymbolsForAddr
SymEnumSymbolsForAddrW
SymEnumSymbolsW
SymEnumTypes
SymEnumTypesByName
SymEnumTypesByNameA
SymEnumTypesByNameW
SymEnumTypesW
SymSearch
SymSearchW
TaskDialogIndirect
TranslateBitmapBits
waveInOpen
waveOutOpen
WdsCliTransferFile
WdsCliTransferImage
WinBioCaptureSampleWithCallback
WinBioEnrollCaptureWithCallback
WinBioIdentifyWithCallback
WinBioLocateSensorWithCallback
WinBioRegisterEventMonitor
WinBioVerifyWithCallback
WlanRegisterNotification
WPUQueryBlockingCallback
WscRegisterForChanges
WsPullBytes
WsPushBytes
WsReadEnvelopeStart
WsRegisterOperationForCancel
WsWriteEnvelopeStart
EnumCalendarInfoExEx
KsCreateFilterFactory
KsMoveIrpsOnCancelableQueue
KsStreamPointerClone
KsStreamPointerScheduleTimeout
MI_Session_Close
MI_Session_Invoke
```