#pragma once
#include "stdafx.h"



typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD* Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
	PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE {
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _LDR_DDAG_NODE
{
	LIST_ENTRY Modules;
	PLDR_SERVICE_TAG_RECORD ServiceTagList;
	ULONG LoadCount;
	ULONG LoadWhileUnloadingCount;
	ULONG LowestLink;
	union {
		LDRP_CSLIST Dependencies;
		SINGLE_LIST_ENTRY RemovalLink;
	};
	LDRP_CSLIST IncomingDependencies;
	LDR_DDAG_STATE State;
	SINGLE_LIST_ENTRY CondenseLink;
	ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

typedef struct _LDR_DEPENDENCY_RECORD
{
	SINGLE_LIST_ENTRY DependencyLink;
	PLDR_DDAG_NODE DependencyNode;
	SINGLE_LIST_ENTRY IncomingDependencyLink;
	PLDR_DDAG_NODE IncomingDependencyNode;
} LDR_DEPENDENCY_RECORD, * PLDR_DEPENDENCY_RECORD;

typedef enum _LDR_DLL_LOAD_REASON {
	LoadReasonStaticDependency,
	LoadReasonStaticForwarderDependency,
	LoadReasonDynamicForwarderDependency,
	LoadReasonDelayloadDependency,
	LoadReasonDynamicLoad,
	LoadReasonAsImageLoad,
	LoadReasonAsDataLoad,
	LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON,
* PLDR_DLL_LOAD_REASON;

typedef struct _SYSTEM_MODULE
{
	ULONG_PTR Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union {
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	union {
		UCHAR FlagGroup[4];
		ULONG Flags;
		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ReservedFlags5 : 3;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT ObsoleteLoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID Lock;
	PLDR_DDAG_NODE DdagNode;
	LIST_ENTRY NodeModuleLink;
	struct _LDRP_LOAD_CONTEXT* LoadContext;
	PVOID ParentDllBase;
	PVOID SwitchBackContext;
	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;
	ULONG_PTR OriginalBase;
	LARGE_INTEGER LoadTime;
	ULONG BaseNameHashValue;
	LDR_DLL_LOAD_REASON LoadReason;
	ULONG ImplicitPathOptions;
	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;



typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	SystemSupportedProcessArchitectures = 0xb5,
} SYSTEM_INFORMATION_CLASS;


typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

//from http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/bigpool.htm
typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;


/*
 * Generic macros that allow you to quickly determine whether
 *  or not a page table entry is present or may forward to a
 *  large page of data, rather than another page table (applies
 *  only to PDPTEs and PDEs)
 */
#define IS_LARGE_PAGE(x)    ( (BOOLEAN)((x >> 7) & 1) )
#define IS_PAGE_PRESENT(x)  ( (BOOLEAN)(x & 1) )

 /*
  * Macros allowing us to more easily deal with page offsets.
  *
  * The *_SHIFT values will allow us to correctly format physical
  *  addresses obtained using the bitfield structures below.
  *
  * The *_OFFSET macro functions will pull out physical page
  *  offsets from virtual addresses. This is only really to make handling
  *  1GB huge pages and 2MB large pages easier.
  * An example: 2MB large pages will require a 21-bit offset to index
  *  page data at one-byte granularity. So if we have the physical base address
  *  of a 2MB large page, in order to get the right physical address for our
  *  target data, we need to add the bottom 21-bits of a virtual address to this
 *   base address. MAXUINT64 is simply a 64-bit value with every possible bit
 *   set (0xFFFFFFFF`FFFFFFFF). In the case of a 2MB large page, we need the
 *   bottom 21-bits from a virtual address to index, so we apply a function which
 *   shifts this MAXUINT64 value by 21-bits, and then inverts all of the bits to
  *  create a mask that can pull out the bottom 21-bits of a target virtual
  *  address. The resulting mask is a value with only the bottom 21-bits of a 64-bit
  *  value set (0x1FFFFF). The below macro functions just make use of previous
  *  macros to make calculating this value easier, which sticks to theory and
  *  avoids magic values that have not yet been explained.
  */

#define PAGE_1GB_SHIFT      30
#define PAGE_1GB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_1GB_SHIFT)) )

#define PAGE_2MB_SHIFT      21
#define PAGE_2MB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_2MB_SHIFT)) )

#define PAGE_4KB_SHIFT      12
#define PAGE_4KB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_4KB_SHIFT)) )

#pragma warning(push)
#pragma warning(disable:4214) // warning C4214: nonstandard extension used: bit field types other than int

  /*
   * This is the format of a virtual address which would map a 4KB underlying
   *  chunk of physical memory
   */
typedef union _VIRTUAL_MEMORY_ADDRESS
{
	struct
	{
		UINT64 PageIndex : 12;  /* 0:11  */
		UINT64 PtIndex : 9;   /* 12:20 */
		UINT64 PdIndex : 9;   /* 21:29 */
		UINT64 PdptIndex : 9;   /* 30:38 */
		UINT64 Pml4Index : 9;   /* 39:47 */
		UINT64 Unused : 16;  /* 48:63 */
	} Bits;
	UINT64 All;
} VIRTUAL_ADDRESS, * PVIRTUAL_ADDRESS;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-12]
 *  "Use of CR3 with 4-Level Paging and 5-level Paging and CR4.PCIDE = 0"
 */
typedef union _DIRECTORY_TABLE_BASE
{
	struct
	{
		UINT64 Ignored0 : 3;    /* 2:0   */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 _Ignored1 : 7;    /* 11:5  */
		UINT64 PhysicalAddress : 36;   /* 47:12 */
		UINT64 _Reserved0 : 16;   /* 63:48 */
	} Bits;
	UINT64 All;
} CR3, DIR_TABLE_BASE;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-15]
 *  "Format of a PML4 Entry (PML4E) that References a Page-Directory-Pointer Table"
 */
typedef union _PML4_ENTRY
{
	struct
	{
		UINT64 Present : 1;    /* 0     */
		UINT64 ReadWrite : 1;    /* 1     */
		UINT64 UserSupervisor : 1;    /* 2     */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 Accessed : 1;    /* 5     */
		UINT64 _Ignored0 : 1;    /* 6     */
		UINT64 _Reserved0 : 1;    /* 7     */
		UINT64 _Ignored1 : 4;    /* 11:8  */
		UINT64 PhysicalAddress : 40;   /* 51:12 */
		UINT64 _Ignored2 : 11;   /* 62:52 */
		UINT64 ExecuteDisable : 1;    /* 63    */
	} Bits;
	UINT64 All;
} PML4E;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-16]
 *  "Table 4-16. Format of a Page-Directory-Pointer-Table Entry (PDPTE) that Maps a 1-GByte Page"
 */
typedef union _PDPT_ENTRY_LARGE
{
	struct
	{
		UINT64 Present : 1;    /* 0     */
		UINT64 ReadWrite : 1;    /* 1     */
		UINT64 UserSupervisor : 1;    /* 2     */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 Accessed : 1;    /* 5     */
		UINT64 Dirty : 1;    /* 6     */
		UINT64 PageSize : 1;    /* 7     */
		UINT64 Global : 1;    /* 8     */
		UINT64 _Ignored0 : 3;    /* 11:9  */
		UINT64 PageAttributeTable : 1;    /* 12    */
		UINT64 _Reserved0 : 17;   /* 29:13 */
		UINT64 PhysicalAddress : 22;   /* 51:30 */
		UINT64 _Ignored1 : 7;    /* 58:52 */
		UINT64 ProtectionKey : 4;    /* 62:59 */
		UINT64 ExecuteDisable : 1;    /* 63    */
	} Bits;
	UINT64 All;
} PDPTE_LARGE;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-17]
 *  "Format of a Page-Directory-Pointer-Table Entry (PDPTE) that References a Page Directory"
 */
typedef union _PDPT_ENTRY
{
	struct
	{
		UINT64 Present : 1;    /* 0     */
		UINT64 ReadWrite : 1;    /* 1     */
		UINT64 UserSupervisor : 1;    /* 2     */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 Accessed : 1;    /* 5     */
		UINT64 _Ignored0 : 1;    /* 6     */
		UINT64 PageSize : 1;    /* 7     */
		UINT64 _Ignored1 : 4;    /* 11:8  */
		UINT64 PhysicalAddress : 40;   /* 51:12 */
		UINT64 _Ignored2 : 11;   /* 62:52 */
		UINT64 ExecuteDisable : 1;    /* 63    */
	} Bits;
	UINT64 All;
} PDPTE;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-18]
 *  "Table 4-18. Format of a Page-Directory Entry that Maps a 2-MByte Page"
 */
typedef union _PD_ENTRY_LARGE
{
	struct
	{
		UINT64 Present : 1;    /* 0     */
		UINT64 ReadWrite : 1;    /* 1     */
		UINT64 UserSupervisor : 1;    /* 2     */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 Accessed : 1;    /* 5     */
		UINT64 Dirty : 1;    /* 6     */
		UINT64 PageSize : 1;    /* 7     */
		UINT64 Global : 1;    /* 8     */
		UINT64 _Ignored0 : 3;    /* 11:9  */
		UINT64 PageAttributeTalbe : 1;    /* 12    */
		UINT64 _Reserved0 : 8;    /* 20:13 */
		UINT64 PhysicalAddress : 29;   /* 49:21 */
		UINT64 _Reserved1 : 2;    /* 51:50 */
		UINT64 _Ignored1 : 7;    /* 58:52 */
		UINT64 ProtectionKey : 4;    /* 62:59 */
		UINT64 ExecuteDisable : 1;    /* 63    */
	} Bits;
	UINT64 All;
} PDE_LARGE;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-19]
 *  "Format of a Page-Directory Entry that References a Page Table"
 */
typedef union _PD_ENTRY
{
	struct
	{
		UINT64 Present : 1;    /* 0     */
		UINT64 ReadWrite : 1;    /* 1     */
		UINT64 UserSupervisor : 1;    /* 2     */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 Accessed : 1;    /* 5     */
		UINT64 _Ignored0 : 1;    /* 6     */
		UINT64 PageSize : 1;    /* 7     */
		UINT64 _Ignored1 : 4;    /* 11:8  */
		UINT64 PhysicalAddress : 38;   /* 49:12 */
		UINT64 _Reserved0 : 2;    /* 51:50 */
		UINT64 _Ignored2 : 11;   /* 62:52 */
		UINT64 ExecuteDisable : 1;    /* 63    */
	} Bits;
	UINT64 All;
} PDE;



//0x1 bytes (sizeof)
union _KWAIT_STATUS_REGISTER
{
	UCHAR Flags;                                                            //0x0
	UCHAR State : 3;                                                          //0x0
	UCHAR Affinity : 1;                                                       //0x0
	UCHAR Priority : 1;                                                       //0x0
	UCHAR Apc : 1;                                                            //0x0
	UCHAR UserApc : 1;                                                        //0x0
	UCHAR Alert : 1;                                                          //0x0
};

//0x430 bytes (sizeof)
struct _KTHREAD
{
	struct _DISPATCHER_HEADER Header;                                       //0x0
	VOID* SListFaultAddress;                                                //0x18
	ULONGLONG QuantumTarget;                                                //0x20
	VOID* InitialStack;                                                     //0x28
	VOID* volatile StackLimit;                                              //0x30
	VOID* StackBase;                                                        //0x38
	ULONGLONG ThreadLock;                                                   //0x40
	volatile ULONGLONG CycleTime;                                           //0x48
	ULONG CurrentRunTime;                                                   //0x50
	ULONG ExpectedRunTime;                                                  //0x54
	VOID* KernelStack;                                                      //0x58
	struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
	struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
	union _KWAIT_STATUS_REGISTER WaitRegister;                              //0x70
	volatile UCHAR Running;                                                 //0x71
	UCHAR Alerted[2];                                                       //0x72
	union
	{
		struct
		{
			ULONG AutoBoostActive : 1;                                        //0x74
			ULONG ReadyTransition : 1;                                        //0x74
			ULONG WaitNext : 1;                                               //0x74
			ULONG SystemAffinityActive : 1;                                   //0x74
			ULONG Alertable : 1;                                              //0x74
			ULONG UserStackWalkActive : 1;                                    //0x74
			ULONG ApcInterruptRequest : 1;                                    //0x74
			ULONG QuantumEndMigrate : 1;                                      //0x74
			ULONG UmsDirectedSwitchEnable : 1;                                //0x74
			ULONG TimerActive : 1;                                            //0x74
			ULONG SystemThread : 1;                                           //0x74
			ULONG ProcessDetachActive : 1;                                    //0x74
			ULONG CalloutActive : 1;                                          //0x74
			ULONG ScbReadyQueue : 1;                                          //0x74
			ULONG ApcQueueable : 1;                                           //0x74
			ULONG ReservedStackInUse : 1;                                     //0x74
			ULONG UmsPerformingSyscall : 1;                                   //0x74
			ULONG TimerSuspended : 1;                                         //0x74
			ULONG SuspendedWaitMode : 1;                                      //0x74
			ULONG SuspendSchedulerApcWait : 1;                                //0x74
			ULONG CetUserShadowStack : 1;                                     //0x74
			ULONG BypassProcessFreeze : 1;                                    //0x74
			ULONG Reserved : 10;                                              //0x74
		};
		LONG MiscFlags;                                                     //0x74
	};
	union
	{
		struct
		{
			ULONG ThreadFlagsSpare : 2;                                       //0x78
			ULONG AutoAlignment : 1;                                          //0x78
			ULONG DisableBoost : 1;                                           //0x78
			ULONG AlertedByThreadId : 1;                                      //0x78
			ULONG QuantumDonation : 1;                                        //0x78
			ULONG EnableStackSwap : 1;                                        //0x78
			ULONG GuiThread : 1;                                              //0x78
			ULONG DisableQuantum : 1;                                         //0x78
			ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
			ULONG DeferPreemption : 1;                                        //0x78
			ULONG QueueDeferPreemption : 1;                                   //0x78
			ULONG ForceDeferSchedule : 1;                                     //0x78
			ULONG SharedReadyQueueAffinity : 1;                               //0x78
			ULONG FreezeCount : 1;                                            //0x78
			ULONG TerminationApcRequest : 1;                                  //0x78
			ULONG AutoBoostEntriesExhausted : 1;                              //0x78
			ULONG KernelStackResident : 1;                                    //0x78
			ULONG TerminateRequestReason : 2;                                 //0x78
			ULONG ProcessStackCountDecremented : 1;                           //0x78
			ULONG RestrictedGuiThread : 1;                                    //0x78
			ULONG VpBackingThread : 1;                                        //0x78
			ULONG ThreadFlagsSpare2 : 1;                                      //0x78
			ULONG EtwStackTraceApcInserted : 8;                               //0x78
		};
		volatile LONG ThreadFlags;                                          //0x78
	};
	volatile UCHAR Tag;                                                     //0x7c
	UCHAR SystemHeteroCpuPolicy;                                            //0x7d
	UCHAR UserHeteroCpuPolicy : 7;                                            //0x7e
	UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
	union
	{
		struct
		{
			UCHAR RunningNonRetpolineCode : 1;                                //0x7f
			UCHAR SpecCtrlSpare : 7;                                          //0x7f
		};
		UCHAR SpecCtrl;                                                     //0x7f
	};
	ULONG SystemCallNumber;                                                 //0x80
	ULONG ReadyTime;                                                        //0x84
	VOID* FirstArgument;                                                    //0x88
	struct _KTRAP_FRAME* TrapFrame;                                         //0x90
	union
	{
		struct _KAPC_STATE ApcState;                                        //0x98
		struct
		{
			UCHAR ApcStateFill[43];                                         //0x98
			CHAR Priority;                                                  //0xc3
			ULONG UserIdealProcessor;                                       //0xc4
		};
	};
	volatile LONGLONG WaitStatus;                                           //0xc8
	struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
	union
	{
		struct _LIST_ENTRY WaitListEntry;                                   //0xd8
		struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
	};
	struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
	VOID* Teb;                                                              //0xf0
	ULONGLONG RelativeTimerBias;                                            //0xf8
	struct _KTIMER Timer;                                                   //0x100
	union
	{
		struct _KWAIT_BLOCK WaitBlock[4];                                   //0x140
		struct
		{
			UCHAR WaitBlockFill4[20];                                       //0x140
			ULONG ContextSwitches;                                          //0x154
		};
		struct
		{
			UCHAR WaitBlockFill5[68];                                       //0x140
			volatile UCHAR State;                                           //0x184
			CHAR Spare13;                                                   //0x185
			UCHAR WaitIrql;                                                 //0x186
			CHAR WaitMode;                                                  //0x187
		};
		struct
		{
			UCHAR WaitBlockFill6[116];                                      //0x140
			ULONG WaitTime;                                                 //0x1b4
		};
		struct
		{
			UCHAR WaitBlockFill7[164];                                      //0x140
			union
			{
				struct
				{
					SHORT KernelApcDisable;                                 //0x1e4
					SHORT SpecialApcDisable;                                //0x1e6
				};
				ULONG CombinedApcDisable;                                   //0x1e4
			};
		};
		struct
		{
			UCHAR WaitBlockFill8[40];                                       //0x140
			struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
		};
		struct
		{
			UCHAR WaitBlockFill9[88];                                       //0x140
			struct _XSTATE_SAVE* XStateSave;                                //0x198
		};
		struct
		{
			UCHAR WaitBlockFill10[136];                                     //0x140
			VOID* volatile Win32Thread;                                     //0x1c8
		};
		struct
		{
			UCHAR WaitBlockFill11[176];                                     //0x140
			struct _UMS_CONTROL_BLOCK* Ucb;                                 //0x1f0
			struct _KUMS_CONTEXT_HEADER* volatile Uch;                      //0x1f8
		};
	};
	union
	{
		volatile LONG ThreadFlags2;                                         //0x200
		struct
		{
			ULONG BamQosLevel : 8;                                            //0x200
			ULONG ThreadFlags2Reserved : 24;                                  //0x200
		};
	};
	ULONG Spare21;                                                          //0x204
	struct _LIST_ENTRY QueueListEntry;                                      //0x208
	union
	{
		volatile ULONG NextProcessor;                                       //0x218
		struct
		{
			ULONG NextProcessorNumber : 31;                                   //0x218
			ULONG SharedReadyQueue : 1;                                       //0x218
		};
	};
	LONG QueuePriority;                                                     //0x21c
	struct _KPROCESS* Process;                                              //0x220
	union
	{
		struct _GROUP_AFFINITY UserAffinity;                                //0x228
		struct
		{
			UCHAR UserAffinityFill[10];                                     //0x228
			CHAR PreviousMode;                                              //0x232
			CHAR BasePriority;                                              //0x233
			union
			{
				CHAR PriorityDecrement;                                     //0x234
				struct
				{
					UCHAR ForegroundBoost : 4;                                //0x234
					UCHAR UnusualBoost : 4;                                   //0x234
				};
			};
			UCHAR Preempted;                                                //0x235
			UCHAR AdjustReason;                                             //0x236
			CHAR AdjustIncrement;                                           //0x237
		};
	};
	ULONGLONG AffinityVersion;                                              //0x238
	union
	{
		struct _GROUP_AFFINITY Affinity;                                    //0x240
		struct
		{
			UCHAR AffinityFill[10];                                         //0x240
			UCHAR ApcStateIndex;                                            //0x24a
			UCHAR WaitBlockCount;                                           //0x24b
			ULONG IdealProcessor;                                           //0x24c
		};
	};
	ULONGLONG NpxState;                                                     //0x250
	union
	{
		struct _KAPC_STATE SavedApcState;                                   //0x258
		struct
		{
			UCHAR SavedApcStateFill[43];                                    //0x258
			UCHAR WaitReason;                                               //0x283
			CHAR SuspendCount;                                              //0x284
			CHAR Saturation;                                                //0x285
			USHORT SListFaultCount;                                         //0x286
		};
	};
	union
	{
		struct _KAPC SchedulerApc;                                          //0x288
		struct
		{
			UCHAR SchedulerApcFill0[1];                                     //0x288
			UCHAR ResourceIndex;                                            //0x289
		};
		struct
		{
			UCHAR SchedulerApcFill1[3];                                     //0x288
			UCHAR QuantumReset;                                             //0x28b
		};
		struct
		{
			UCHAR SchedulerApcFill2[4];                                     //0x288
			ULONG KernelTime;                                               //0x28c
		};
		struct
		{
			UCHAR SchedulerApcFill3[64];                                    //0x288
			struct _KPRCB* volatile WaitPrcb;                               //0x2c8
		};
		struct
		{
			UCHAR SchedulerApcFill4[72];                                    //0x288
			VOID* LegoData;                                                 //0x2d0
		};
		struct
		{
			UCHAR SchedulerApcFill5[83];                                    //0x288
			UCHAR CallbackNestingLevel;                                     //0x2db
			ULONG UserTime;                                                 //0x2dc
		};
	};
	struct _KEVENT SuspendEvent;                                            //0x2e0
	struct _LIST_ENTRY ThreadListEntry;                                     //0x2f8
	struct _LIST_ENTRY MutantListHead;                                      //0x308
	UCHAR AbEntrySummary;                                                   //0x318
	UCHAR AbWaitEntryCount;                                                 //0x319
	UCHAR AbAllocationRegionCount;                                          //0x31a
	CHAR SystemPriority;                                                    //0x31b
	ULONG SecureThreadCookie;                                               //0x31c
	struct _KLOCK_ENTRY* LockEntries;                                       //0x320
	struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x328
	struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x330
	UCHAR PriorityFloorCounts[16];                                          //0x338
	UCHAR PriorityFloorCountsReserved[16];                                  //0x348
	ULONG PriorityFloorSummary;                                             //0x358
	volatile LONG AbCompletedIoBoostCount;                                  //0x35c
	volatile LONG AbCompletedIoQoSBoostCount;                               //0x360
	volatile SHORT KeReferenceCount;                                        //0x364
	UCHAR AbOrphanedEntrySummary;                                           //0x366
	UCHAR AbOwnedEntryCount;                                                //0x367
	ULONG ForegroundLossTime;                                               //0x368
	union
	{
		struct _LIST_ENTRY GlobalForegroundListEntry;                       //0x370
		struct
		{
			struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x370
			ULONGLONG InGlobalForegroundList;                               //0x378
		};
	};
	LONGLONG ReadOperationCount;                                            //0x380
	LONGLONG WriteOperationCount;                                           //0x388
	LONGLONG OtherOperationCount;                                           //0x390
	LONGLONG ReadTransferCount;                                             //0x398
	LONGLONG WriteTransferCount;                                            //0x3a0
	LONGLONG OtherTransferCount;                                            //0x3a8
	struct _KSCB* QueuedScb;                                                //0x3b0
	volatile ULONG ThreadTimerDelay;                                        //0x3b8
	union
	{
		volatile LONG ThreadFlags3;                                         //0x3bc
		struct
		{
			ULONG ThreadFlags3Reserved : 8;                                   //0x3bc
			ULONG PpmPolicy : 2;                                              //0x3bc
			ULONG ThreadFlags3Reserved2 : 22;                                 //0x3bc
		};
	};
	ULONGLONG TracingPrivate[1];                                            //0x3c0
	VOID* SchedulerAssist;                                                  //0x3c8
	VOID* volatile AbWaitObject;                                            //0x3d0
	ULONG ReservedPreviousReadyTimeValue;                                   //0x3d8
	ULONGLONG KernelWaitTime;                                               //0x3e0
	ULONGLONG UserWaitTime;                                                 //0x3e8
	union
	{
		struct _LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry;           //0x3f0
		struct
		{
			struct _SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry; //0x3f0
			ULONGLONG InGlobalUpdateVpThreadPriorityList;                   //0x3f8
		};
	};
	LONG SchedulerAssistPriorityFloor;                                      //0x400
	ULONG Spare28;                                                          //0x404
	ULONGLONG EndPadding[5];                                                //0x408
};

#pragma warning(pop)

//0x4 bytes (sizeof)
typedef struct _MM_GRAPHICS_VAD_FLAGS
{
	ULONG Lock : 1;                                                           //0x0
	ULONG LockContended : 1;                                                  //0x0
	ULONG DeleteInProgress : 1;                                               //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG VadType : 3;                                                        //0x0
	ULONG Protection : 5;                                                     //0x0
	ULONG PreferredNode : 6;                                                  //0x0
	ULONG PageSize : 2;                                                       //0x0
	ULONG PrivateMemoryAlwaysSet : 1;                                         //0x0
	ULONG WriteWatch : 1;                                                     //0x0
	ULONG FixedLargePageSize : 1;                                             //0x0
	ULONG ZeroFillPagesOptional : 1;                                          //0x0
	ULONG GraphicsAlwaysSet : 1;                                              //0x0
	ULONG GraphicsUseCoherentBus : 1;                                         //0x0
	ULONG GraphicsNoCache : 1;                                                //0x0
	ULONG GraphicsPageProtection : 3;                                         //0x0
} MM_GRAPHICS_VAD_FLAGS, * PMM_GRAPHICS_VAD_FLAGS;

//0x4 bytes (sizeof)
typedef struct _MM_PRIVATE_VAD_FLAGS
{
	ULONG Lock : 1;                                                           //0x0
	ULONG LockContended : 1;                                                  //0x0
	ULONG DeleteInProgress : 1;                                               //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG VadType : 3;                                                        //0x0
	ULONG Protection : 5;                                                     //0x0
	ULONG PreferredNode : 6;                                                  //0x0
	ULONG PageSize : 2;                                                       //0x0
	ULONG PrivateMemoryAlwaysSet : 1;                                         //0x0
	ULONG WriteWatch : 1;                                                     //0x0
	ULONG FixedLargePageSize : 1;                                             //0x0
	ULONG ZeroFillPagesOptional : 1;                                          //0x0
	ULONG Graphics : 1;                                                       //0x0
	ULONG Enclave : 1;                                                        //0x0
	ULONG ShadowStack : 1;                                                    //0x0
	ULONG PhysicalMemoryPfnsReferenced : 1;                                   //0x0
} MM_PRIVATE_VAD_FLAGS, * PMM_PRIVATE_VAD_FLAGS;

//0x4 bytes (sizeof)
typedef struct _MM_SHARED_VAD_FLAGS
{
	ULONG Lock : 1;                                                           //0x0
	ULONG LockContended : 1;                                                  //0x0
	ULONG DeleteInProgress : 1;                                               //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG VadType : 3;                                                        //0x0
	ULONG Protection : 5;                                                     //0x0
	ULONG PreferredNode : 6;                                                  //0x0
	ULONG PageSize : 2;                                                       //0x0
	ULONG PrivateMemoryAlwaysClear : 1;                                       //0x0
	ULONG PrivateFixup : 1;                                                   //0x0
	ULONG HotPatchAllowed : 1;                                                //0x0
}MM_SHARED_VAD_FLAGS, * PMM_SHARED_VAD_FLAGS;

//0x8 bytes (sizeof)
typedef struct _MI_VAD_SEQUENTIAL_INFO
{
	ULONGLONG Length : 12;                                                    //0x0
	ULONGLONG Vpn : 52;                                                       //0x0
}MI_VAD_SEQUENTIAL_INFO, * PMI_VAD_SEQUENTIAL_INFO;

//0x8 bytes (sizeof)
typedef struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;                                             //0x0
			ULONGLONG Waiting : 1;                                            //0x0
			ULONGLONG Waking : 1;                                             //0x0
			ULONGLONG MultipleShared : 1;                                     //0x0
			ULONGLONG Shared : 60;                                            //0x0
		};
		ULONGLONG Value;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
} EX_PUSH_LOCKD, * PEX_PUSH_LOCKD;

//0x4 bytes (sizeof)
typedef struct _MMVAD_FLAGS1
{
	ULONG CommitCharge : 31;                                                  //0x0
	ULONG MemCommit : 1;                                                      //0x0
}MMVAD_FLAGS1, * PMMVAD_FLAGS1;

//0x4 bytes (sizeof)
typedef struct _MMVAD_FLAGS2
{
	ULONG FileOffset : 24;                                                    //0x0
	ULONG Large : 1;                                                          //0x0
	ULONG TrimBehind : 1;                                                     //0x0
	ULONG Inherit : 1;                                                        //0x0
	ULONG NoValidationNeeded : 1;                                             //0x0
	ULONG PrivateDemandZero : 1;                                              //0x0
	ULONG Spare : 3;                                                          //0x0
}MMVAD_FLAGS2, * PMMVAD_FLAGS2;

//0x4 bytes (sizeof)
typedef struct _MMVAD_FLAGS
{
	ULONG Lock : 1;                                                           //0x0
	ULONG LockContended : 1;                                                  //0x0
	ULONG DeleteInProgress : 1;                                               //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG VadType : 3;                                                        //0x0
	ULONG Protection : 5;                                                     //0x0
	ULONG PreferredNode : 6;                                                  //0x0
	ULONG PageSize : 2;                                                       //0x0
	ULONG PrivateMemory : 1;                                                  //0x0
}MMVAD_FLAGS, * PMMVAD_FLAGS;

//0x40 bytes (sizeof)
typedef struct _MMVAD_SHORT
{
	union
	{
		struct
		{
			struct _MMVAD_SHORT* NextVad;                                   //0x0
			VOID* ExtraCreateInfo;                                          //0x8
		};
		struct _RTL_BALANCED_NODE VadNode;                                  //0x0
	};
	ULONG StartingVpn;                                                      //0x18
	ULONG EndingVpn;                                                        //0x1c
	UCHAR StartingVpnHigh;                                                  //0x20
	UCHAR EndingVpnHigh;                                                    //0x21
	UCHAR CommitChargeHigh;                                                 //0x22
	UCHAR SpareNT64VadUChar;                                                //0x23
	LONG ReferenceCount;                                                    //0x24
	struct _EX_PUSH_LOCK PushLock;                                          //0x28
	union
	{
		ULONG LongFlags;                                                    //0x30
		struct _MMVAD_FLAGS VadFlags;                                       //0x30
		struct _MM_PRIVATE_VAD_FLAGS PrivateVadFlags;                       //0x30
		struct _MM_GRAPHICS_VAD_FLAGS GraphicsVadFlags;                     //0x30
		struct _MM_SHARED_VAD_FLAGS SharedVadFlags;                         //0x30
		volatile ULONG VolatileVadLong;                                     //0x30
	} u;                                                                    //0x30
	union
	{
		ULONG LongFlags1;                                                   //0x34
		struct _MMVAD_FLAGS1 VadFlags1;                                     //0x34
	} u1;                                                                   //0x34
	struct _MI_VAD_EVENT_BLOCK* EventList;                                  //0x38
}MMVAD_SHORT, * PMMVAD_SHORT;

typedef struct _MMVAD
{
	struct _MMVAD_SHORT Core;                                               //0x0
	union
	{
		ULONG LongFlags2;                                                   //0x40
		volatile struct _MMVAD_FLAGS2 VadFlags2;                            //0x40
	} u2;                                                                   //0x40
	struct _SUBSECTION* Subsection;                                         //0x48
	struct _MMPTE* FirstPrototypePte;                                       //0x50
	struct _MMPTE* LastContiguousPte;                                       //0x58
	struct _LIST_ENTRY ViewLinks;                                           //0x60
	struct _EPROCESS* VadsProcess;                                          //0x70
	union
	{
		struct _MI_VAD_SEQUENTIAL_INFO SequentialVa;                        //0x78
		struct _MMEXTEND_INFO* ExtendedInfo;                                //0x78
	} u4;                                                                   //0x78
	struct _FILE_OBJECT* FileObject;                                        //0x80
}MMVAD, * PMMVAD;


//0x8 bytes (sizeof)
struct _MMPTE_HARDWARE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Dirty1 : 1;                                                     //0x0
	ULONGLONG Owner : 1;                                                      //0x0
	ULONGLONG WriteThrough : 1;                                               //0x0
	ULONGLONG CacheDisable : 1;                                               //0x0
	ULONGLONG Accessed : 1;                                                   //0x0
	ULONGLONG Dirty : 1;                                                      //0x0
	ULONGLONG LargePage : 1;                                                  //0x0
	ULONGLONG Global : 1;                                                     //0x0
	ULONGLONG CopyOnWrite : 1;                                                //0x0
	ULONGLONG Unused : 1;                                                     //0x0
	ULONGLONG Write : 1;                                                      //0x0
	ULONGLONG PageFrameNumber : 36;                                           //0x0
	ULONGLONG ReservedForHardware : 4;                                        //0x0
	ULONGLONG ReservedForSoftware : 4;                                        //0x0
	ULONGLONG WsleAge : 4;                                                    //0x0
	ULONGLONG WsleProtection : 3;                                             //0x0
	ULONGLONG NoExecute : 1;                                                  //0x0
};
//0x8 bytes (sizeof)
struct _MMPTE_PROTOTYPE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG DemandFillProto : 1;                                            //0x0
	ULONGLONG HiberVerifyConverted : 1;                                       //0x0
	ULONGLONG ReadOnly : 1;                                                   //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Combined : 1;                                                   //0x0
	ULONGLONG Unused1 : 4;                                                    //0x0
	LONGLONG ProtoAddress : 48;                                               //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE_SOFTWARE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG PageFileReserved : 1;                                           //0x0
	ULONGLONG PageFileAllocated : 1;                                          //0x0
	ULONGLONG ColdPage : 1;                                                   //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG PageFileLow : 4;                                                //0x0
	ULONGLONG UsedPageTableEntries : 10;                                      //0x0
	ULONGLONG ShadowStack : 1;                                                //0x0
	ULONGLONG Unused : 5;                                                     //0x0
	ULONGLONG PageFileHigh : 32;                                              //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE_TIMESTAMP
{
	ULONGLONG MustBeZero : 1;                                                 //0x0
	ULONGLONG Unused : 3;                                                     //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG PageFileLow : 4;                                                //0x0
	ULONGLONG Reserved : 16;                                                  //0x0
	ULONGLONG GlobalTimeStamp : 32;                                           //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE_TRANSITION
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Write : 1;                                                      //0x0
	ULONGLONG Spare : 1;                                                      //0x0
	ULONGLONG IoTracker : 1;                                                  //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG PageFrameNumber : 36;                                           //0x0
	ULONGLONG Unused : 16;                                                    //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE_SUBSECTION
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Unused0 : 3;                                                    //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG ColdPage : 1;                                                   //0x0
	ULONGLONG Unused1 : 3;                                                    //0x0
	ULONGLONG ExecutePrivilege : 1;                                           //0x0
	LONGLONG SubsectionAddress : 48;                                          //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE_LIST
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG OneEntry : 1;                                                   //0x0
	ULONGLONG filler0 : 2;                                                    //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG filler1 : 16;                                                   //0x0
	ULONGLONG NextEntry : 36;                                                 //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE
{
	union
	{
		ULONGLONG Long;                                                     //0x0
		volatile ULONGLONG VolatileLong;                                    //0x0
		struct _MMPTE_HARDWARE Hard;                                        //0x0
		struct _MMPTE_PROTOTYPE Proto;                                      //0x0
		struct _MMPTE_SOFTWARE Soft;                                        //0x0
		struct _MMPTE_TIMESTAMP TimeStamp;                                  //0x0
		struct _MMPTE_TRANSITION Trans;                                     //0x0
		struct _MMPTE_SUBSECTION Subsect;                                   //0x0
		struct _MMPTE_LIST List;                                            //0x0
	} u;                                                                    //0x0
};