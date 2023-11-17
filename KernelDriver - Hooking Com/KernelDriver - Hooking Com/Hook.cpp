#include "Functions.h"

bool CallHook(void* kernelFunctionAddress)
{
	DebugMessage("CallKernelFunction Called");

	//checking if kernelfunctionaddress is valid and not NULL
	if (!kernelFunctionAddress)	
		return false;

	//defining function to be the function we are going to hook
	PVOID* function = reinterpret_cast<PVOID*>(GetDriverExport("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceStatistics"));

	//checking if function is valid and not NULL
	if (!function)
		return false;

	//Grabbs Orignal Bytes
	PVOID originalBytes = function[12];

	DebugMessage("Original Bytes: %llx\n", originalBytes);

	//Original code to the function we are hooking
	BYTE hookBytes[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	//define
	BYTE mov = 0x48;
	BYTE rax = 0xB8;
	BYTE jmp = 0xFF;
	BYTE jrax = 0xE0;

	//Bytes we inject to function
	BYTE MovRax[] = { mov, rax }; // move rax, our function address
	BYTE JmpRax[] = { jmp, jrax }; //jmp rax , jumps to our function

	//fills our hook function with zero memory
	RtlSecureZeroMemory(&hookBytes, sizeof(hookBytes));

	//Getting hook address
	uintptr_t hookAddress = reinterpret_cast<uintptr_t>(kernelFunctionAddress);

	//copys shell code to original bytes                                    //mov rax                                      //orig bytes = (0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	memcpy((PVOID)((ULONG_PTR)hookBytes), &MovRax, sizeof(MovRax));
	//copys shell code + hook address to original bytes                     //mov rax, (0xFFFF) address to our function    //orig bytes = (0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00)
	memcpy((PVOID)((ULONG_PTR)hookBytes + sizeof(MovRax)), &hookAddress, sizeof(void*));
	//copys shell code + hook address + shell code end to original bytes    //jmp rax                                      ////orig bytes = (0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0)
	memcpy((PVOID)((ULONG_PTR)hookBytes + sizeof(MovRax) + sizeof(void*)), &JmpRax, sizeof(JmpRax));

	DebugMessage("Bytes to Hook: %llx\n", hookBytes);

	//Writes the final hook bytes to dxgkrnl.sys 
	//mov rax, 0xffffff
	//jmp rax
	//rax = ourfunction address
	WriteToReadOnlyMemory(function, &hookBytes, sizeof(hookBytes));

	return true;
}

NTSTATUS Hook(PVOID calledParameter)
{
	//Define
	NULL_MEMORY* instructions = (NULL_MEMORY*)calledParameter;

	//Request Base
	if (instructions->requestBase == TRUE)
	{
		DebugMessage("Request Base Called");

		//Defines
		ANSI_STRING as;
		UNICODE_STRING moduleName;

		//storing module name into AS as AnsiString
		RtlInitAnsiString(&as, instructions->moduleName);
		//storing as to modulename as UnicodeString
		RtlAnsiStringToUnicodeString(&moduleName, &as, TRUE);

		//Getting Process
		PEPROCESS process;
		PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);

		//Call Dll Base to get base address
		ULONG64 baseAddress;
		baseAddress = GetDllBase(process, moduleName);

		//storing base address into instructions baseAddress
		instructions->baseAddress = baseAddress;

		DebugMessage("baseAddress: 0x%p\n", baseAddress);

		//Release UnicodeString moduleName
		RtlFreeUnicodeString(&moduleName);
	}

	//Read Memory
	if (instructions->read == TRUE)
	{
		DebugMessage("Read Memory Called");

		//Defines
		uintptr_t address = instructions->address;
		PVOID pBuff = instructions->output;
		ULONG size = instructions->size;
		SIZE_T bytes;

		//Getting Process
		PEPROCESS process;
		PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);

		//Reading Memory from Process
		MmCopyVirtualMemory(process, (void*)address, PsGetCurrentProcess(), (void*)pBuff, size, KernelMode, &bytes);
	}

	return STATUS_SUCCESS;
}
