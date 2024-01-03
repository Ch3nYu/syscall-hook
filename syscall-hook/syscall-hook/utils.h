#include "stdafx.h"


#define UniqueProcessId_Offset 0x440 //EPROCESS
#define ActiveProcessLinks_Offset 0x448 //EPROCESS
#define UserDirectoryTableBase_Offset 0x388 //KPROCESS
#define DirectoryTableBase_Offset 0x28 //KPROCESS
#define SectionBaseAddress_Offset 0x520 //EPROCESS
#define ApcState_Offset 0x98 //KTHREAD
#define Process_Offset 0x20 //KAPC_STATE

#define PAGE_OFFSET_SIZE 12
static const uintptr_t PMASK = (~0xfull << 8) & 0xfffffffffull;

struct virtual_address_t {
	union {
		struct {
			unsigned long long offset : 12;         // Offset within page
			unsigned long long pt_index : 9;        // Index in the page table
			unsigned long long pd_index : 9;        // Index in the page directory
			unsigned long long pdpt_index : 9;      // Index in the page directory pointer table
			unsigned long long pml4_index : 9;      // Index in the PML4 table
			unsigned long long reserved : 16;       // Reserved bits
		};
		uintptr_t value;                           // Complete 64-bit virtual address
	};
};

namespace Utils
{
	PIMAGE_NT_HEADERS getHeader(PVOID module) {
		return (PIMAGE_NT_HEADERS)((PBYTE)module + PIMAGE_DOS_HEADER(module)->e_lfanew);
	}

	PBYTE FindPattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask) {

		auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
			{
				for (auto x = buffer; *mask; pattern++, mask++, x++) {
					auto addr = *(BYTE*)(pattern);
					if (addr != *x && *mask != '?')
						return FALSE;
				}

				return TRUE;
			};

		for (auto x = 0; x < size - strlen(mask); x++) {

			auto addr = (PBYTE)module + x;
			if (checkMask(addr, pattern, mask))
				return addr;
		}

		return NULL;
	}

	PBYTE FindPattern(PVOID base, LPCSTR pattern, LPCSTR mask)
	{
		auto header = getHeader(base);
		auto section = IMAGE_FIRST_SECTION(header);

		for (auto x = 0; x < header->FileHeader.NumberOfSections; x++, section++) {
			if (!memcmp(section->Name, skCrypt(".text"), 5) || !memcmp(section->Name, skCrypt("PAGE"), 4)) {
				auto addr = FindPattern((PBYTE)base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
				if (addr) {
					return addr;
				}
			}
		}

		return NULL;
	}

	PVOID GetModuleBase(LPCWSTR moduleName)
	{

		PLIST_ENTRY ModuleList = PsLoadedModuleList;
		if (!ModuleList)
			return NULL;

		UNICODE_STRING pmoduleName;
		RtlInitUnicodeString(&pmoduleName, moduleName);

		for (PLIST_ENTRY entry = ModuleList; entry != ModuleList->Blink; entry = entry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY Datatable = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (Datatable->BaseDllName.Length == pmoduleName.Length && RtlEqualUnicodeString(&Datatable->BaseDllName, &pmoduleName, TRUE)) {
				return  Datatable->DllBase;
			}
		}

		return NULL;
	}

	PVOID GetSystemModuleExport(LPCWSTR module_name, LPCSTR routine_name)
	{
		PVOID lpModule = GetModuleBase(module_name);

		return lpModule ? RtlFindExportedRoutineByName(lpModule, routine_name) : NULL;
	}

	uintptr_t GetProcessCr3(PEPROCESS pProcess)
	{
		uintptr_t DirectoryTableBase = *reinterpret_cast<uintptr_t*>((uintptr_t)pProcess + DirectoryTableBase_Offset);
		if (!DirectoryTableBase)
		{
			uintptr_t UserDirectoryTableBase = *reinterpret_cast<uintptr_t*>((uintptr_t)pProcess + UserDirectoryTableBase_Offset);
			return UserDirectoryTableBase;
		}
		return DirectoryTableBase;
	}

	uintptr_t GetKernelDirBase()
	{
		return *reinterpret_cast<uintptr_t*>((uintptr_t)PsGetCurrentProcess() + DirectoryTableBase_Offset);
	}

	NTSTATUS ReadPhysicalAddress2(uintptr_t TargetAddress, PVOID  lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
	{
		if (!TargetAddress)
			return STATUS_UNSUCCESSFUL;

		MM_COPY_ADDRESS AddrToRead = { 0 };
		AddrToRead.PhysicalAddress.QuadPart = TargetAddress;
		return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
	}

	NTSTATUS ReadPhysicalAddress(uintptr_t TargetAddress, PVOID  lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
	{
		if (!TargetAddress)
			return STATUS_UNSUCCESSFUL;

		MM_COPY_ADDRESS AddrToRead = { 0 };

		AddrToRead.PhysicalAddress.QuadPart = TargetAddress;
		PVOID NonPagedBuffer = ExAllocatePool(NonPagedPool, Size);

		if (!NonPagedBuffer)
			return STATUS_UNSUCCESSFUL;

		MmCopyMemory(NonPagedBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);

		memcpy(lpBuffer, NonPagedBuffer, Size);


		ExFreePoolWithTag(NonPagedBuffer, 0);

		return  STATUS_SUCCESS;
	}

	NTSTATUS WritePhysicalAddress(uintptr_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
	{
		if (!TargetAddress)
			return STATUS_UNSUCCESSFUL;

		PHYSICAL_ADDRESS SourcePhysicalAddress = { NULL };
		SourcePhysicalAddress.QuadPart = TargetAddress;
		PVOID  MappedIoSpace = MmMapIoSpaceEx(SourcePhysicalAddress, Size, PAGE_READWRITE);

		if (!MappedIoSpace)
			return STATUS_UNSUCCESSFUL;


		memcpy(MappedIoSpace, lpBuffer, Size);

		*BytesWritten = Size;
		MmUnmapIoSpace(MappedIoSpace, Size);

		return STATUS_SUCCESS;
	}

	uintptr_t TranslateLinearAddress(uintptr_t directoryTableBase, uintptr_t virtualAddress)
	{
		directoryTableBase &= ~0xf;
		size_t readsize;

		virtual_address_t virtual_address;
		virtual_address.value = virtualAddress;

		_MMPTE pml4e = { 0 };
		ReadPhysicalAddress2(directoryTableBase + 8 * virtual_address.pml4_index, &pml4e, 8, &readsize);
		if (!pml4e.u.Hard.Valid)
			return 0;

		_MMPTE pdpte = { 0 };
		ReadPhysicalAddress2((pml4e.u.Hard.PageFrameNumber << 12) + 8 * virtual_address.pdpt_index, &pdpte, 8, &readsize);
		if (!pdpte.u.Hard.Valid)
			return 0;

		_MMPTE pde = { 0 };
		ReadPhysicalAddress2((pdpte.u.Hard.PageFrameNumber << 12) + 8 * virtual_address.pd_index, &pde, 8, &readsize);
		if (!pde.u.Hard.Valid)
			return 0;

		_MMPTE pte = { 0 };
		ReadPhysicalAddress2((pde.u.Hard.PageFrameNumber << 12) + 8 * virtual_address.pt_index, &pte, 8, &readsize);
		if (!pte.u.Hard.Valid)
			return 0;



		return (pte.u.Hard.PageFrameNumber << 12) + virtual_address.offset;
	}

	uintptr_t TranslateLinearAddress2(uintptr_t directoryTableBase, uintptr_t virtualAddress) {
		directoryTableBase &= ~0xf;


		uintptr_t pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
		uintptr_t pte = ((virtualAddress >> 12) & (0x1ffll));
		uintptr_t pt = ((virtualAddress >> 21) & (0x1ffll));
		uintptr_t pd = ((virtualAddress >> 30) & (0x1ffll));
		uintptr_t pdp = ((virtualAddress >> 39) & (0x1ffll));

		SIZE_T readsize = 0;
		uintptr_t pdpe = 0;
		ReadPhysicalAddress(directoryTableBase + 8 * pdp, &pdpe, sizeof(pdpe), &readsize);
		if (~pdpe & 1)
			return 0;

		uintptr_t pde = 0;
		ReadPhysicalAddress((pdpe & PMASK) + 8 * pd, &pde, sizeof(pde), &readsize);
		if (~pde & 1)
			return 0;

		/* 1GB large page, use pde's 12-34 bits */
		if (pde & 0x80)
			return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

		uintptr_t pteAddr = 0;
		ReadPhysicalAddress((pde & PMASK) + 8 * pt, &pteAddr, sizeof(pteAddr), &readsize);
		if (~pteAddr & 1)
			return 0;

		/* 2MB large page */
		if (pteAddr & 0x80)
			return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

		virtualAddress = 0;
		ReadPhysicalAddress((pteAddr & PMASK) + 8 * pte, &virtualAddress, sizeof(virtualAddress), &readsize);
		virtualAddress &= PMASK;

		if (!virtualAddress)
			return 0;

		return virtualAddress + pageOffset;
	}

	uintptr_t GetProcessBaseAddress(PEPROCESS pProcess);

	uintptr_t BruteforceCr3(PEPROCESS peprocess)
	{
		uintptr_t base_address = GetProcessBaseAddress(peprocess);
		if (!base_address)
			return 0;

		virtual_address_t virtual_address;
		virtual_address.value = base_address;

		PPHYSICAL_MEMORY_RANGE physical_ranges = MmGetPhysicalMemoryRanges();
		for (int i = 0; /**/; i++)
		{
			PHYSICAL_MEMORY_RANGE current_element = { 0 };
			memcpy(&current_element, &physical_ranges[i], sizeof(PHYSICAL_MEMORY_RANGE));
			if (!current_element.BaseAddress.QuadPart || !current_element.NumberOfBytes.QuadPart)
				return 0;

			uintptr_t current_physical = current_element.BaseAddress.QuadPart;
			for (uintptr_t j = 0; j < (current_element.NumberOfBytes.QuadPart / 0x1000); j++, current_physical += 0x1000)
			{
				size_t retbytes = 0;
				_MMPTE pml4e = { 0 };
				ReadPhysicalAddress2(current_physical + 8 * virtual_address.pml4_index, &pml4e, 8, &retbytes);
				if (!pml4e.u.Hard.Valid)
					continue;

				_MMPTE pdpte = { 0 };
				ReadPhysicalAddress2((pml4e.u.Hard.PageFrameNumber << 12) + 8 * virtual_address.pdpt_index, &pdpte, 8, &retbytes);
				if (!pdpte.u.Hard.Valid)
					continue;

				_MMPTE pde = { 0 };
				ReadPhysicalAddress2((pdpte.u.Hard.PageFrameNumber << 12) + 8 * virtual_address.pd_index, &pde, 8, &retbytes);
				if (!pde.u.Hard.Valid)
					continue;

				_MMPTE pte = { 0 };
				ReadPhysicalAddress2((pde.u.Hard.PageFrameNumber << 12) + 8 * virtual_address.pt_index, &pte, 8, &retbytes);
				if (!pte.u.Hard.Valid)
					continue;

				uintptr_t physical_base = TranslateLinearAddress(current_physical, base_address);
				if (!physical_base)
					continue;

				char buffer[sizeof(IMAGE_DOS_HEADER)];
				ReadPhysicalAddress2(physical_base, buffer, sizeof(IMAGE_DOS_HEADER), &retbytes);

				PIMAGE_DOS_HEADER header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
				if (header->e_magic != IMAGE_DOS_SIGNATURE)
					continue;


				return current_physical;
			}
		}

		return 0;
	}

	NTSTATUS ReadVirtual(uintptr_t dirbase, uintptr_t address, void* buffer, SIZE_T size, SIZE_T* read)
	{
		uintptr_t paddress = TranslateLinearAddress2(dirbase, address);
		return ReadPhysicalAddress2(paddress, buffer, size, read);
	}

	NTSTATUS WriteVirtual(uintptr_t dirbase, uintptr_t address, void* buffer, SIZE_T size, SIZE_T* written)
	{
		uintptr_t paddress = TranslateLinearAddress2(dirbase, address);
		return ReadPhysicalAddress2(paddress, buffer, size, written);
	}

	
	NTSTATUS GetEProcess(INT ProcessID, PEPROCESS* ep)
	{
		LIST_ENTRY ActiveProcessLinks;
		SIZE_T ret;


		ReadVirtual(GetKernelDirBase(), (uintptr_t)PsGetCurrentProcess() + ActiveProcessLinks_Offset, reinterpret_cast<void*>(&ActiveProcessLinks), sizeof(ActiveProcessLinks), &ret);
		while (TRUE)
		{
			INT NextProcessID = NULL;
			uintptr_t NextLink = reinterpret_cast<uintptr_t>(ActiveProcessLinks.Flink);
			PEPROCESS Process = PEPROCESS(NextLink - ActiveProcessLinks_Offset);


			ReadVirtual(GetKernelDirBase(), (uintptr_t)Process + UniqueProcessId_Offset, reinterpret_cast<void*>(&NextProcessID), sizeof(NextProcessID), &ret);
			ReadVirtual(GetKernelDirBase(), (uintptr_t)Process + ActiveProcessLinks_Offset, reinterpret_cast<void*>(&ActiveProcessLinks), sizeof(ActiveProcessLinks), &ret);

			if (NextProcessID == ProcessID)
			{
				*ep = Process;

				return STATUS_SUCCESS;
			}

			if (!Process || Process == PsGetCurrentProcess())
				break;

		}

		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS ReadProcessMemory(uintptr_t DirectoryTableBase, uintptr_t Address, uintptr_t AllocatedBuffer, SIZE_T size, SIZE_T* read)
	{
		NTSTATUS Status = NULL;

		if (!DirectoryTableBase)
			return STATUS_UNSUCCESSFUL;

		SIZE_T CurOffset = NULL;
		SIZE_T TotalSize = size;
		while (TotalSize)
		{

			uintptr_t CurPhysAddr = TranslateLinearAddress(DirectoryTableBase, (ULONG64)Address + CurOffset);
			if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

			ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
			SIZE_T BytesRead = 0;
			Status = ReadPhysicalAddress(CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
			TotalSize -= BytesRead;
			CurOffset += BytesRead;
			if (Status != STATUS_SUCCESS) break;
			if (BytesRead == 0) break;
		}

		*read = CurOffset;
		return Status;
	}

	NTSTATUS WriteProcessMemory(uintptr_t DirectoryTableBase, uintptr_t Address, uintptr_t AllocatedBuffer, SIZE_T size, SIZE_T* written)
	{
		NTSTATUS Status = NULL;

		if (!DirectoryTableBase)
			return STATUS_UNSUCCESSFUL;

		SIZE_T CurOffset = NULL;
		SIZE_T TotalSize = size;

		while (TotalSize)
		{
			uintptr_t CurPhysAddr = TranslateLinearAddress(DirectoryTableBase, (ULONG64)Address + CurOffset);
			if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

			ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
			SIZE_T BytesWritten = 0;
			Status = WritePhysicalAddress(CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);
			TotalSize -= BytesWritten;
			CurOffset += BytesWritten;
			if (Status != STATUS_SUCCESS) break;
			if (BytesWritten == 0) break;
		}

		*written = CurOffset;
		return Status;
	}

	uintptr_t GetProcessBaseAddress(PEPROCESS pProcess)
	{
		uintptr_t BaseAddress = NULL;

		BaseAddress = *(uintptr_t*)((uintptr_t)pProcess + SectionBaseAddress_Offset);

		if (!BaseAddress)
			return NULL;

		return BaseAddress;
	}

	uintptr_t SwapProcess(uintptr_t _Process)
	{
		
		uintptr_t CurrentThread = (uintptr_t)KeGetCurrentThread();

		uintptr_t ApcState = *(uintptr_t*)(CurrentThread + 0x98);
		uintptr_t Process = *(uintptr_t*)(ApcState + 0x20);
		*(uintptr_t*)(ApcState + 0x20) = _Process;

		uintptr_t DirectoryTableBase = *(uintptr_t*)(_Process + 0x28);
		__writecr3(DirectoryTableBase);

		return Process;
	}
}