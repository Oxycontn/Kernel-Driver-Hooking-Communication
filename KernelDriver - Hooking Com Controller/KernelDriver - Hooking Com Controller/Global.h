#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <string_view>
#include <cstdint>
#include <vector>

#include "Functions.h"

typedef struct _NULL_MEMORY
{
	void* buffer_address;
	UINT_PTR address;
	ULONGLONG size;
	ULONG pid;
	BOOLEAN write;
	BOOLEAN read;
	BOOLEAN requestBase;
	void* output;
	const char* moduleName;
	ULONG64 baseAddress;
}NULL_MEMORY;
