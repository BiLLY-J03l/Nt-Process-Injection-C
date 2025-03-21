# Nt-Process-Injection-C
## Process Injection with C and the Native undocumeneted API

- The malware uses the Native API, which is considered stealthier.

- It allocates the encrypted shellcode in the .data section

- First, it tries to get a handle to the NTDLL.dll then it uses a predefined file native.h and get the addresses of each function we wanna use.

- Then it enumrates the processes running on the machine and picks notepad.exe, you can change that in the enum_processes() function.

- Then it gets a handle to the requested process.

- It decrypts the shellcode and allocates memory for the shellcode with READWRITE permissions.

- Then it writes the shellcode to the allocated buffer.

- Then it adds the exec bit to the allocated memory permissions.

- Then it creates the thread with the malicious shellcode in the target process address space.


## listener options

  ![image](https://github.com/user-attachments/assets/a6e4bf09-4e4a-4758-acfa-e17d1e0dccc2)


## EXECUTION:

  ![image](https://github.com/user-attachments/assets/52f34f18-b1d8-4a62-9616-1ad66df5ec56)


  ![image](https://github.com/user-attachments/assets/44b75a35-7fd6-48b8-979a-03abbc1238a5)


### UPDATED:
- you don't need to pass the pid arg, just open up notepad.exe and the malware will automatically enumerates the processes on the system till it get to it.

- VirusTotal Analysis

  ![image](https://github.com/user-attachments/assets/6fd9674d-f556-46db-8361-6b19676ec771)


  


