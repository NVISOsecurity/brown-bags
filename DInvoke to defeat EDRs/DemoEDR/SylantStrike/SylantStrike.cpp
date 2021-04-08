// SylantStrike.cpp : Hooked API implementations
//

#include "pch.h"
#include "framework.h"
#include "SylantStrike.h"

#include <cstdio>

//Pointer to the trampoline function used to call the original API
pNtAllocateVirtualMemory pOriginalNtAllocateVirtualMemory = nullptr;
pNtWriteVirtualMemory pOriginalNtWriteVirtualMemory = nullptr;
pNtProtectVirtualMemory pOriginalNtProtectVirtualMemory = nullptr;
pNtCreateThreadEx pOriginalNtCreateThreadEx = nullptr;
HANDLE suspiciousHandle = nullptr;
PVOID suspiciousBaseAddress = nullptr;

DWORD(NTAPI NtAllocateVirtualMemory)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG_PTR ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect)
{
	if (Protect == PAGE_EXECUTE_READWRITE)
	{
		MessageBox(nullptr, TEXT("Allocating RWX memory are we? - DETECTED."), TEXT("Custom EDR powered by @EthicalChaos"), MB_OK);
		suspiciousHandle = ProcessHandle;
	}
	return pOriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}


DWORD(NTAPI NtWriteVirtualMemory)(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG NumberOfBytesToWrite, OUT PULONG NumberOfBytesWritten)
{
	if (ProcessHandle == suspiciousHandle)
		MessageBox(nullptr, TEXT("Writing memory are we? - DETECTED."), TEXT("Custom EDR powered by @EthicalChaos"), MB_OK);
	suspiciousBaseAddress = BaseAddress;
	return pOriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}


DWORD NTAPI NtProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PULONG NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection)
{
	if (ProcessHandle == suspiciousHandle)
	{
		MessageBox(nullptr, TEXT("Protecting virtual memory are we? - DETECTED."), TEXT("Custom EDR powered by @EthicalChaos"), MB_OK);
	}
	return pOriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}


DWORD NTAPI NtCreateThreadEx(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN LPVOID ObjectAttributes, IN HANDLE ProcessHandle, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter, IN BOOL CreateSuspended, IN ULONG StackZeroBits, IN ULONG SizeOfStackCommit, IN ULONG SizeOfStackReserve, OUT LPVOID lpBytesBuffer)
{
	if ((lpStartAddress == (LPTHREAD_START_ROUTINE)suspiciousBaseAddress))
	{
		MessageBox(nullptr, TEXT("OK that does it. I am not letting you create a new thread! Killing your process now!!"), TEXT("Custom EDR powered by @EthicalChaos"), MB_OK);
		TerminateProcess(GetCurrentProcess(), 0xdead1337);
		return 0;
	}
	return pOriginalNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
}





