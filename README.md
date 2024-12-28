# Nt-Process-Injection-C
Process Injection with C and the Native undocumeneted API

-The malware uses the Nativ Api, which is considered stealthier.

-First, the malware tries to get a handle to the NTDLL.dll then it uses a predefined file native.h and get the addresses of each function we wanna use.

-Then it takes an arg to the process you want to inject the shellcode into.

-Then it gets a handle to the requested process and allocates memory for the shellcode with READWRITE permissions


