#include "Global.h"

DWORD GetProcessIdByName(const wchar_t* processName)
{
    DWORD processId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(processEntry);

        if (Process32First(hSnap, &processEntry))
        {
            do
            {
                if (!_wcsicmp(processEntry.szExeFile, processName))
                {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &processEntry));
        }
    }

    CloseHandle(hSnap);
    return processId;
}

template<typename ... Arg>
uint64_t CallHook(const Arg ... args)
{
	LoadLibrary(TEXT("user32.dll"));

	void* FunctionPTR = GetProcAddress(LoadLibrary(TEXT("win32u.dll")),"NtQueryCompositionSurfaceStatistics");

    auto function = static_cast<uint64_t(_stdcall*)(Arg...)>(FunctionPTR);

	return function(args ...);
}

ULONG64 GetDllBase(const char* moduleName, ULONG pid)
{
	NULL_MEMORY instructions = { 0 };

    instructions.pid = pid;
    instructions.moduleName = moduleName;
	instructions.requestBase = TRUE;

	CallHook(&instructions);

	uintptr_t base;
	base = instructions.baseAddress;

	return base;
}
