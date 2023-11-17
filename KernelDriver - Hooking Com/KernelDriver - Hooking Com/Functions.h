#pragma once

#include "Global.h"

//Message Function
#define DebugMessage(x, ...) DbgPrintEx(0,0,x,__VA_ARGS__)

//Driver Functions
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
extern "C" NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);

//Hook Functions
bool CallHook(void* kernalFunctionAddress);
NTSTATUS Hook(PVOID calledParameter);

//Memory Functions
PVOID GetDriverBase(const char* module_name);
PVOID GetDriverExport(const char* moduleName, LPCSTR routineName);
bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size);
ULONG64 GetDllBase(PEPROCESS process, UNICODE_STRING moduleNamne);