#pragma warning (disable: 4996 4267)

#include "Functions.h"

PVOID GetDriverBase(const char* moduleName)
{
	//Defines
	ULONG bytes = 0;

	//Retrieves the specified system information, stores info into bytes
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	//checks if prevois line was NULL or not
	if (!bytes)
		return 0;

	//The ExAllocatePoolWithTag routine allocates pool memory of the specified type and returns a pointer to the allocated block.
	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x486F6F6B);

	//Retrieves the specified system information, stores info into bytes
	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	//check to see if previous line returnes SUS or not
	if (!NT_SUCCESS(status))
		return 0;

	//stores the module(s) information into struct MODULE_INFOMATION pointer to module
	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

	//Defines
	PVOID DriverBaseAddress = 0;

	//Loops thru all module(s)
	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		//comparess name of modules to the name given
		if (strcmp((char*)module[i].FullPathName, moduleName) == 0)
		{
			//if correct store base and size
			DriverBaseAddress = module[i].ImageBase;
			break;
		}
	}

	//if there are modules then exit the pool
	if (modules)
		ExFreePoolWithTag(modules, 0);

	//check to see if module base is valid and not NULL
	if (!DriverBaseAddress)
	{
		DebugMessage("Failed to Grab Driver Base");
		return 0;
	}
	else
		DebugMessage("Driver Base: 0x%p\n", DriverBaseAddress);

	return DriverBaseAddress;
}

PVOID GetDriverExport(const char* moduleName, LPCSTR routineName)
{
	//Store Address of Driver into DriverAddress
	PVOID DriverAddress = GetDriverBase(moduleName);

	//Check to see if Driver Address is NULL
	if (!DriverAddress)
		return 0;

	//Grab the Offset of routine name
	PVOID DriverBaseExport = RtlFindExportedRoutineByName(DriverAddress, routineName);

	if (!DriverBaseExport)
		DebugMessage("Failed to Grab Kernel Base Export");
	else
		DebugMessage("Routine Base: 0x%p\n", DriverBaseExport);
	
	return DriverBaseExport;
}

bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size)
{
	DebugMessage("Write To Read Only Memory Called");

	//The IoAllocateMdl routine allocates a memory descriptor list (MDL)
	PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, 0);

	//checking if mdl is valid
	if (!mdl)
	{
		DebugMessage("mdl Failed");
		return false;
	}
	else
		DebugMessage("mdl Sussesfull");

	//The MmProbeAndLockPages routine probes the specified virtual memory pages, makes them resident, 
	// and locks them in memory (say for a DMA transfer). 
	// This ensures the pages cannot be freed and reallocated while a device driver (or hardware) is still using them.

	//this locked the memory page we want to modify
	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

	//The MmMapLockedPagesSpecifyCache routine maps the physical pages that are described by an MDL to a virtual address, 
	// and enables the caller to specify the cache attribute that is used to create the mapping.

	//mapp the mdl after the memory papges where loced in the prevois line to a virtual address to call
	PVOID mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);

	//The MmProtectMdlSystemAddress routine sets the protection type for a memory address range.

	//setting mdl to read and write memory
	MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

	//writing buffer to (mapping) that is the virtual address of the memory page we grabbed
	memcpy(mapping, buffer, size);

	//The MmUnmapLockedPages routine releases a mapping that was set up by a preceding call to the MmMapLockedPages or MmMapLockedPagesSpecifyCache routine.

	//release the virtual address we created
	MmUnmapLockedPages(mapping, mdl);

	//The MmUnlockPages routine unlocks the physical pages that are described by the specified memory descriptor list (MDL).

	//unlocks the memory pages we locked
	MmUnlockPages(mdl);

	//frees the MDL from memory
	IoFreeMdl(mdl);

	//return true
	return true;
}

ULONG64 GetDllBase(PEPROCESS process, UNICODE_STRING moduleNamne)
{
	//Getting Process Info into PPEB
	PPEB pPeb = PsGetProcessPeb(process);

	if (!pPeb)
		return 0;

	//Define
	KAPC_STATE state;

	//Attach to Process for Memory Region
	KeStackAttachProcess(process, &state);

	//Store all Modules from Memory Region into pLdr
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	//if pLdr is Null Detach from Memory Region
	if (!pLdr)
	{
		//Dettach from Memory Region
		KeUnstackDetachProcess(&state);
		//Return 0 if NULL
		return 0;
	}

	//Loop thru all modules till we find the one that matches the one we look for
	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink; list != &pLdr->InLoadOrderModuleList; list = (PLIST_ENTRY)list->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &moduleNamne, TRUE) == NULL)
		{
			//Store Base Address into type baseAddress
			ULONG64 baseAddress = (ULONG64)pEntry->DllBase;
			//Dettach from Memory Region
			KeUnstackDetachProcess(&state);
			//return Base
			return baseAddress;
		}

	}

	//Dettach from Memory Region
	KeUnstackDetachProcess(&state);

	//Return 0
	return 0;
}