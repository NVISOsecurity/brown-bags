// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the CYLANTSTRIKE_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// CYLANTSTRIKE_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef CYLANTSTRIKE_EXPORTS
#define CYLANTSTRIKE_API __declspec(dllexport)
#else
#define CYLANTSTRIKE_API __declspec(dllimport)
#endif

typedef DWORD(NTAPI* pNtAllocateVirtualMemory)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG_PTR ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
typedef DWORD(NTAPI* pNtWriteVirtualMemory)(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG NumberOfBytesToWrite, OUT PULONG NumberOfBytesWritten);
typedef DWORD(NTAPI* pNtProtectVirtualMemory)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PULONG NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
typedef DWORD(NTAPI* pNtCreateThreadEx)(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN LPVOID ObjectAttributes, IN HANDLE ProcessHandle, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter, IN BOOL CreateSuspended, IN ULONG StackZeroBits, IN ULONG SizeOfStackCommit, IN ULONG SizeOfStackReserve, OUT LPVOID lpBytesBuffer);

extern pNtProtectVirtualMemory pOriginalNtProtectVirtualMemory;
extern pNtAllocateVirtualMemory pOriginalNtAllocateVirtualMemory;
extern pNtCreateThreadEx pOriginalNtCreateThreadEx;
extern pNtWriteVirtualMemory pOriginalNtWriteVirtualMemory;


DWORD NTAPI NtProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PULONG NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
DWORD NTAPI NtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG NumberOfBytesToWrite, OUT PULONG NumberOfBytesWritten);
DWORD NTAPI NtAllocateVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG_PTR ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
DWORD NTAPI NtCreateThreadEx(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN LPVOID ObjectAttributes, IN HANDLE ProcessHandle, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter, IN BOOL CreateSuspended, IN ULONG StackZeroBits, IN ULONG SizeOfStackCommit, IN ULONG SizeOfStackReserve, OUT LPVOID lpBytesBuffer);



