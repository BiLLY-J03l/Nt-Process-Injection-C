# Nt-Process-Injection-C
Process Injection with C and the Native undocumeneted API

-The malware uses the Nativ Api, which is considered stealthier.

-The malware allocates the encrypted shellcode in the .data section

-First, the malware tries to get a handle to the NTDLL.dll then it uses a predefined file native.h and get the addresses of each function we wanna use.

-Then it takes an arg to the process you want to inject the shellcode into.

-Then it gets a handle to the requested process.

-It decrypts the shellcode and allocates memory for the shellcode with READWRITE permissions.

-Then it writes the shellcode to the allocated buffer.

-Then it adds the exec bit to the allocated memory permissions.

-Then it creates the thread with the malicious shellcode.
