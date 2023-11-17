
//Hook Functions
DWORD GetProcessIdByName(const wchar_t* processName);
ULONG64 GetDllBase(const char* moduleName, ULONG pid);
template<typename ... Arg>
uint64_t CallHook(const Arg ... args);
template <typename type>
type ReadVirtualMem(ULONG ProcessID, uintptr_t ReadAddress, SIZE_T Size);