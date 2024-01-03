#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
#include <intrin.h>
#include "structs.h"
#include "skCrypter.h"

#define RELATIVE_ADDR(addr, size) ((UINT_PTR)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))

#define IOCTL_COMMAND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct
{
    int Mode;
    int ProcessID;
    uintptr_t MagicCode;
    uintptr_t Address;
    uintptr_t Buffer;
    DWORD Protect;
    size_t Size;
    LPCWSTR ModuleName;
    MEMORY_BASIC_INFORMATION MBI;
} Request_;


enum code
{
    PROTECT,
    UNPROTECT,
    SET_PROCESS,
    SET_CR3,
    READ_MEMORY_PHY,
    WRITE_MEMORY_PHY,
    READ_MEMORY,
    WRITE_MEMORY,
    GET_BASE_ADDRESS,
    GET_BASE_ADDRESS_WITH_NAME,
    PROTECT_MEMORY,
    ALLOC_MEMORY,
    FREE_MEMORY,
    QUERY_MEMORY,
    UNLOAD_SELF,
    DELETE_FILE
};

extern "C" NTKERNELAPI PLIST_ENTRY PsLoadedModuleList;

extern "C" NTKERNELAPI void* RtlFindExportedRoutineByName(_In_ void* ImageBase, _In_ PCCH RoutineName);

extern "C" NTKERNELAPI NTSTATUS
MmCopyVirtualMemory(
    IN PEPROCESS FromProcess,
    IN CONST VOID* FromAddress,
    IN PEPROCESS ToProcess,
    OUT PVOID ToAddress,
    IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T NumberOfBytesCopied
    );

extern "C" NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection);

extern "C" NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);

extern "C" NTSTATUS NTAPI NtTraceControl(
    ULONG FunctionCode,
    PVOID InBuffer,
    ULONG InBufferLen,
    PVOID OutBuffer,
    ULONG OutBufferLen,
    PULONG ReturnLength);

extern "C" NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    _In_ PVOID ModuleAddress
);

VOID(*KiStackAttachProcess)(PRKPROCESS PROCESS, int Count, PRKAPC_STATE ApcState);
VOID(*KiUnstackDetachProcess)(PRKAPC_STATE ApcState, int Count);

extern "C" NTKERNELAPI NTSTATUS IoCreateDriver(
    _In_ PUNICODE_STRING DriverName, OPTIONAL
    _In_ PDRIVER_INITIALIZE InitializationFunction
);

#include "memory.h"
#include "utils.h"
