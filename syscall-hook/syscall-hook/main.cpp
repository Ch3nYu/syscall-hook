#include <ntifs.h>
#include <ntimage.h>
#include <cstdint>
#include <intrin.h>

#include "stdafx.h"

ULONGLONG KernelBase = 0;

typedef enum _ETW_TRACE_CONTROL_CODE {
    EtwStartLoggerCode = 1,
    EtwStopLoggerCode = 2,
    EtwQueryLoggerCode = 3,
    EtwUpdateLoggerCode = 4,
    EtwFlushLoggerCode = 5,
    EtwConnect = 11,
    EtwActivityIdCreate = 12,
    EtwWdiScenarioCode = 13,
    EtwDisconnect = 14,
    EtwRegisterGuid = 15,
    EtwReceiveNotification = 16,
    EtwEnableGuid = 17,
    EtwSendReplyDataBlock = 18,
    EtwReceiveReplyDataBlock = 19,

    EtwWdiSemUpdate = 20
} ETW_TRACE_CONTROL_CODE;


#define WNODE_FLAG_TRACED_GUID			0x00020000  // denotes a trace
#define EVENT_TRACE_BUFFERING_MODE      0x00000400  // Buffering mode only
#define EVENT_TRACE_FLAG_SYSTEMCALL     0x00000080  // system calls

const GUID CkclSessionGuid = { 0x9E814AAD, 0x3204, 0x11D2, { 0x9A, 0x82, 0x0, 0x60, 0x8, 0xA8, 0x69, 0x39 } };
typedef struct _WNODE_HEADER
{
    ULONG BufferSize;        // Size of entire buffer inclusive of this ULONG
    ULONG ProviderId;    // Provider Id of driver returning this buffer
    union
    {
        ULONG64 HistoricalContext;  // Logger use
        struct
        {
            ULONG Version;           // Reserved
            ULONG Linkage;           // Linkage field reserved for WMI
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    union
    {
        ULONG CountLost;         // Reserved
        HANDLE KernelHandle;     // Kernel handle for data block
        LARGE_INTEGER TimeStamp; // Timestamp as returned in units of 100ns
        // since 1/1/1601
    } DUMMYUNIONNAME2;
    GUID Guid;                  // Guid for data block returned with results
    ULONG ClientContext;
    ULONG Flags;             // Flags, see below
} WNODE_HEADER, * PWNODE_HEADER;

typedef struct _EVENT_TRACE_PROPERTIES {
    WNODE_HEADER	Wnode;
    ULONG			BufferSize;
    ULONG			MinimumBuffers;
    ULONG			MaximumBuffers;
    ULONG			MaximumFileSize;
    ULONG			LogFileMode;
    ULONG			FlushTimer;
    ULONG			EnableFlags;
    LONG			AgeLimit;
    ULONG			NumberOfBuffers;
    ULONG			FreeBuffers;
    ULONG			EventsLost;
    ULONG			BuffersWritten;
    ULONG			LogBuffersLost;
    ULONG			RealTimeBuffersLost;
    HANDLE			LoggerThreadId;
    ULONG			LogFileNameOffset;
    ULONG			LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
    ULONG64					Unknown[3];
    UNICODE_STRING			ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;

void(*HalCollectPmcCountersOrig)(ULONGLONG arg1, ULONGLONG* arg2);
__int64(*HvlGetQpcBiasOrig)();
ULONGLONG HvlpReferenceTscPage = 0;
ULONGLONG HvlGetQpcBias = 0;


ULONGLONG EtwpDebuggerData = 0;
ULONGLONG CkclWmiLoggerContext = 0;
PVOID SystemCallEntryPage = 0;
ULONGLONG* GetCpuClock = 0;
ULONGLONG GetCpuClockOriginal = 0;

void(*IfhpCallback)(unsigned int SystemCallIndex, PVOID* SystemCallFunction);

ULONGLONG SelfGetCpuClock()
{
    if (ExGetPreviousMode() == KernelMode) return __rdtsc();

    PKTHREAD current_thread = (PKTHREAD)__readgsqword(0x188);

    unsigned int call_index = *(unsigned int*)((ULONGLONG)current_thread + 0x80);

    PVOID* StackMax = (PVOID*)__readgsqword(0x1a8);
    PVOID* StackFrame = (PVOID*)_AddressOfReturnAddress();

    for (PVOID* CurrentStack = StackMax; CurrentStack > StackFrame; --CurrentStack)
    {
        unsigned long* l_value = (unsigned long*)CurrentStack;
        if (*l_value != 0x501802) continue;

        --CurrentStack;

        unsigned short* s_value = (unsigned short*)CurrentStack;
        if (*s_value != 0xF33) continue;

        for (; CurrentStack < StackMax; ++CurrentStack)
        {
            ULONGLONG* ull_value = (ULONGLONG*)CurrentStack;
            if (!(PAGE_ALIGN(*ull_value) >= SystemCallEntryPage && PAGE_ALIGN(*ull_value) < (PVOID)((ULONGLONG)SystemCallEntryPage + (PAGE_SIZE * 2)))) continue;

            PVOID* system_call_function = &CurrentStack[9];

            if (IfhpCallback) 
                IfhpCallback(call_index, system_call_function);

            break;
        }
        break;
    }

    return __rdtsc();
}

__int64 hkHvlGetQpcBias()
{
    SelfGetCpuClock();

    return *((ULONGLONG*)HvlpReferenceTscPage + 3);
}

NTSTATUS IfhpModifyTraceSettings(ETW_TRACE_CONTROL_CODE Operation)
{
    CKCL_TRACE_PROPERTIES* property = (CKCL_TRACE_PROPERTIES*)ExAllocatePool(NonPagedPool, PAGE_SIZE);
    if (!property)   
        return STATUS_MEMORY_NOT_ALLOCATED;
    
    wchar_t* provider_name = (wchar_t*)ExAllocatePool(NonPagedPool, 256 * sizeof(wchar_t));
    if (!provider_name)
    {
        ExFreePool(property);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    RtlZeroMemory(property, PAGE_SIZE);
    RtlZeroMemory(provider_name, 256 * sizeof(wchar_t));

    RtlCopyMemory(provider_name, L"Circular Kernel Context Logger", sizeof(L"Circular Kernel Context Logger"));
    RtlInitUnicodeString(&property->ProviderName, (const wchar_t*)provider_name);

    GUID ckcl_session_guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

    property->Wnode.BufferSize = PAGE_SIZE;
    property->Wnode.Flags = 0x00020000;
    property->Wnode.Guid = ckcl_session_guid;
    property->Wnode.ClientContext = 3;
    property->BufferSize = sizeof(unsigned long);
    property->MinimumBuffers = 2;
    property->MaximumBuffers = 2;
    property->LogFileMode = 0x00000400;

    unsigned long length = 0;
    if (Operation == ETW_TRACE_CONTROL_CODE::EtwUpdateLoggerCode) 
        property->EnableFlags = 0x00000080;

    NTSTATUS status = NtTraceControl(Operation, property, PAGE_SIZE, property, PAGE_SIZE, &length);

    ExFreePool(provider_name);
    ExFreePool(property);

    return status;
}

void IfhRelease()
{
    if (NT_SUCCESS(IfhpModifyTraceSettings(EtwStopLoggerCode)))
    {
        IfhpModifyTraceSettings(EtwStartLoggerCode);
    }
}

VOID DriverUnload(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);

    IfhRelease();

    *GetCpuClock =  GetCpuClockOriginal;

    *(PVOID*)(HvlGetQpcBias) = HvlGetQpcBiasOrig;
}

PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
    ULONG_PTR Instr = (ULONG_PTR)Instruction;
    LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
    PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
    return ResolvedAddr;
}

NTSTATUS IfhInitialize(PVOID InfinityHookCallback)
{

    NTSTATUS Status = IfhpModifyTraceSettings(EtwUpdateLoggerCode);
    if (!NT_SUCCESS(Status))
    {
        Status = IfhpModifyTraceSettings(EtwStartLoggerCode);

        if (!NT_SUCCESS(Status))
        {
            return Status;
        }

        Status = IfhpModifyTraceSettings(EtwUpdateLoggerCode);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }

    PBYTE addr = Utils::FindPattern((PVOID)KernelBase, "\x8B\x1D\x00\x00\x00\x00\x4C\x8D\x8C\x24\x00\x00\x00\x00", "xx????xxxx????");
    EtwpDebuggerData = ((ULONGLONG)ResolveRelativeAddress(addr, 2, 6) + 0x4);


    if (!EtwpDebuggerData)
    {
        return STATUS_UNSUCCESSFUL;
    }

    ULONGLONG* EtwpDebuggerDataSilo = *(ULONGLONG**)((ULONGLONG)EtwpDebuggerData + 0x10);

    CkclWmiLoggerContext = EtwpDebuggerDataSilo[2];

    GetCpuClock = (ULONGLONG*)((ULONGLONG)CkclWmiLoggerContext + 0x28);

    addr = Utils::FindPattern((PVOID)KernelBase, "\xC6\x45\xAB\x02", "xxxx");
    SystemCallEntryPage = PAGE_ALIGN(addr); //KiSystemServiceUser

    if (!SystemCallEntryPage)
    {
        return STATUS_UNSUCCESSFUL;
    }

    IfhpCallback = decltype(IfhpCallback)(InfinityHookCallback);

    addr = Utils::FindPattern((PVOID)KernelBase, "\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x40\x18\xC3", "xxx????xxxxx");
    HvlpReferenceTscPage = (ULONGLONG)ResolveRelativeAddress(addr, 3, 7);

    if (!HvlpReferenceTscPage)
    {
        return STATUS_UNSUCCESSFUL;
    }

    GetCpuClockOriginal = (ULONGLONG)(*GetCpuClock);
    *GetCpuClock =  2;
   
    addr = Utils::FindPattern((PVOID)KernelBase, "\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x03\xD8", "xxx????x????xxx");
    HvlGetQpcBias = (ULONGLONG)ResolveRelativeAddress(addr, 3, 7);

    if (!HvlGetQpcBias)
    {
        return STATUS_UNSUCCESSFUL;
    }
    *(PVOID*)&HvlGetQpcBiasOrig = *(PVOID*)(HvlGetQpcBias);
    *(PVOID*)(HvlGetQpcBias) = hkHvlGetQpcBias;
  
    return STATUS_SUCCESS;
}


NTSTATUS(*NtCreateFileOrig)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    if (ObjectAttributes &&
        ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer)
    {
        wchar_t* name = (wchar_t*)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
        if (name)
        {
            RtlZeroMemory(name, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
            RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

            if (wcsstr(name, L"testhook"))
            {
                DbgPrintEx(0, 0, "Called %ws \n", name);

                ExFreePool(name);

                return STATUS_ACCESS_DENIED;
            }

            ExFreePool(name);
        }
    }

    return NtCreateFileOrig(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}



void SyscallStub(unsigned int SystemCallIndex, PVOID* SystemCallFunction)
{
    if (*SystemCallFunction == NtCreateFileOrig)
        *SystemCallFunction = MyNtCreateFile;

}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT arg1, PUNICODE_STRING arg2)
{
    arg1->DriverUnload = DriverUnload;

    KernelBase = (ULONGLONG)Utils::GetModuleBase(L"ntoskrnl.exe");

    UNICODE_STRING str;
    RtlInitUnicodeString(&str, L"NtCreateFile");

    NtCreateFileOrig = decltype(NtCreateFileOrig)(MmGetSystemRoutineAddress(&str));


	return IfhInitialize(SyscallStub);
}