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


-listener options

  ![image](https://github.com/user-attachments/assets/a6e4bf09-4e4a-4758-acfa-e17d1e0dccc2)


-EXECUTION:

  ![image](https://github.com/user-attachments/assets/52f34f18-b1d8-4a62-9616-1ad66df5ec56)


  ![image](https://github.com/user-attachments/assets/44b75a35-7fd6-48b8-979a-03abbc1238a5)


-VirusTotal Analysis

  ![image](https://github.com/user-attachments/assets/6fd9674d-f556-46db-8361-6b19676ec771)


  


