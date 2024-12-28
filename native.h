#pragma once
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib,"user32.lib")
#include <windows.h>
#include <stdio.h>
#include <winbase.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)


// -------------------- STRUCTS -------------------- //


typedef struct _UNICODE_STRING
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    WCHAR* Buffer;                                                          //0x8
} UNICODE_STRING , *PUNICODE_STRING; 

//0x30 bytes (sizeof)
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;                                                           //0x0
    VOID* RootDirectory;                                                    //0x8
    struct _UNICODE_STRING* ObjectName;                                     //0x10
    ULONG Attributes;                                                       //0x18
    VOID* SecurityDescriptor;                                               //0x20
    VOID* SecurityQualityOfService;                                         //0x28
} ObjectAttributes , *PCOBJECT_ATTRIBUTES; 

//0x10 bytes (sizeof)
typedef struct _CLIENT_ID
{
    VOID* UniqueProcess;                                                    //0x0
    VOID* UniqueThread;                                                     //0x8
}CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef struct _INITIAL_TEB
{
    struct
    {
        PVOID OldStackBase;
        PVOID OldStackLimit;
    } OldInitialTeb;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;


//ALREADY DEFINED
/*
//0x8 bytes (sizeof)
typedef struct _LUID
{
    ULONG LowPart;                                                          //0x0
    LONG HighPart;                                                          //0x4
} LUID , *PLUID; 

//0xc bytes (sizeof)
typedef struct _LUID_AND_ATTRIBUTES
{
    struct _LUID Luid;                                                      //0x0
    ULONG Attributes;                                                       //0x8
} LUID_AND_ATTRIBUTES , *PLUID_AND_ATTRIBUTES; 

//0x10 bytes (sizeof)
typedef struct _TOKEN_PRIVILEGES
{
    ULONG PrivilegeCount;                                                   //0x0
    struct _LUID_AND_ATTRIBUTES Privileges[1];                              //0x4
} TOKEN_PRIVILEGES , *PTOKEN_PRIVILEGES; 
*/
// -------------------- FUNCTION PROTOTYPES -------------------- //

//OpenProcess
//NtOpenProcess
typedef NTSTATUS (NTAPI * NtOpenProcess)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );

//CreateThread
//NtCreateThreadEx
typedef NTSTATUS (NTAPI * NtCreateThreadEx)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
);

typedef NTSTATUS (NTAPI * NtGetContextThread)(
    _In_ HANDLE ThreadHandle,
    _Inout_ PCONTEXT ThreadContext
);

typedef NTSTATUS (NTAPI * NtSetContextThread)(
    _In_ HANDLE ThreadHandle,
    _In_ PCONTEXT ThreadContext
);

//NtCreateThread
typedef NTSTATUS (NTAPI * NtCreateThread)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _Out_ PCLIENT_ID ClientId,
    _In_ PCONTEXT ThreadContext,
    _In_ PINITIAL_TEB InitialTeb,
    _In_ BOOLEAN CreateSuspended
);

//NtResumeThread
typedef NTSTATUS (NTAPI * NtResumeThread)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
);

//NtCreateProcessEx
typedef NTSTATUS (NTAPI * NtCreateProcessEx)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags, // PROCESS_CREATE_FLAGS_*
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle,
    _Reserved_ ULONG Reserved // JobMemberLevel
);


typedef NTSTATUS (NTAPI * NtCreateProcess)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritObjectTable,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle
);

typedef NTSTATUS (NTAPI * NtClose)(
    _In_ _Post_ptr_invalid_ HANDLE Handle
);

//VirtualAllocEx
//NtAllocateVirtualMemory
typedef NTSTATUS (NTAPI * NtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);


//WriteProcessMemory
//NtWriteVirtualMemory
typedef NTSTATUS (NTAPI * NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

//VirtualProtect
//NtProtectVirtualMemory
typedef NTSTATUS (NTAPI * NtProtectVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

//WaitForSingleObject
//NtWaitForSingleObject
typedef NTSTATUS (NTAPI * NtWaitForSingleObject)(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

//NtFreeVirtualMemory
typedef NTSTATUS (NTAPI * NtFreeVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
);

// --- ESCALATION PRIVILLEGES --- //

//NtOpenProcessToken
typedef NTSTATUS (NTAPI * NtOpenProcessToken)(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE TokenHandle
);

//NtAdjustPrivilegesToken
typedef NTSTATUS (NTAPI * NtAdjustPrivilegesToken)(
    _In_ HANDLE TokenHandle,
    _In_ BOOLEAN DisableAllPrivileges,
    _In_opt_ PTOKEN_PRIVILEGES NewState,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
    _Out_opt_ PULONG ReturnLength
);







