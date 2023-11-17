#include "Global.h"

template <typename type>
type ReadVirtualMem(ULONG ProcessID, uintptr_t ReadAddress, SIZE_T Size)
{
	type Buffer;

	NULL_MEMORY instructions;

	instructions.pid = ProcessID;
	instructions.address = ReadAddress;
	instructions.output = &Buffer;
	instructions.size = Size;
	instructions.read = TRUE;

	CallHook(&instructions);

	return Buffer;
}

int main()
{
	ULONG pid = GetProcessIdByName(L"cs2.exe");

	if (pid == 0)
		printf("Process ID Not Found");
	else
		printf("Process ID Found: %d\n", pid);

	ULONG64 clientBaseAddress = GetDllBase("client.dll", pid);

	if (clientBaseAddress == 0)
		printf("Failed to get Client.Dll");
	else
		printf("Grabbed Client.Dll: 0x%p\n", clientBaseAddress);

	ULONG64 engineBaseAddress = GetDllBase("engine2.dll", pid);

	if (engineBaseAddress == 0)
		printf("Failed to get Engine.Dll");
	else
		printf("Grabbed Engine.Dll: 0x%p\n", engineBaseAddress);

	while (true)
	{
		uintptr_t LocalPlayerPawn = ReadVirtualMem<uintptr_t>(pid, clientBaseAddress + 0x16BC4B8, sizeof(uintptr_t));

		int myHealth = ReadVirtualMem<int>(pid, LocalPlayerPawn + 0x32C, sizeof(int));

		printf("Player Health: %d\n", myHealth);

		Sleep(600);
	}

	return 0;
}