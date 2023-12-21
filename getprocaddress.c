/*
    getprocaddress.c
    a single-file library to obtain the address of the GetProcAddress function.
    (C) 2023, MIT License, https://github.com/martona/getprocaddress
    12/21/2023, 0.1.0, initial release

    This is useful for writing code that does not depend on being compile-time linked
    to any external libraries, including the CRT.

    Include this file in your project. It should be pretty friction-free.
    
    Call the following function to obtain the module handle of kernel32:

    ///////////////////////////////////////////////////////////////////////////////////////
    ptr get_kernel32_modulehandle()
        returns the module handle for kernel32.dll

    Then call the following function to obtain the address of GetProcAddress.
    We define GetProcAddress_t as a function pointer type for convenience.

    ///////////////////////////////////////////////////////////////////////////////////////
    GetProcAddress_t get_getprocaddress(ptr modulehandle)
        returns the address of the GetProcAddress function
        given a module handle (that can be obtained from get_kernel32_modulehandle))
*/

#ifndef _GETPROCADDRESS_C
#define _GETPROCADDRESS_C
#define _GETPROCADDRESS_DEBUG 0
#if _GETPROCADDRESS_DEBUG
#include <stdio.h>
#include <windows.h>
#define GETPROCADDRESS_DEBUG(format, ...) printf(format, ##__VA_ARGS__)
#else
#define GETPROCADDRESS_DEBUG(format, ...)
#endif

#if !defined(_BASIC_TYPES_DEFINED)
#define _BASIC_TYPES_DEFINED
typedef char                 i8;
typedef short               i16;
typedef int                 i32;
typedef long long           i64;
typedef unsigned char        u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef void*               ptr;
typedef unsigned short      wchar;
#endif

// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_dos_header
// the only struct we need
#pragma pack(push, 1)
typedef struct _gpa_IMAGE_EXPORT_DIRECTORY {
    u32   Characteristics;
    u32   TimeDateStamp;
    u16   MajorVersion;
    u16   MinorVersion;
    u32   Name;
    u32   Base;
    u32   NumberOfFunctions;
    u32   NumberOfNames;
    u32   AddressOfFunctions;
    u32   AddressOfNames;
    u32   AddressOfNameOrdinals;
} gpa_IMAGE_EXPORT_DIRECTORY, *gpa_PIMAGE_EXPORT_DIRECTORY;
#pragma pack(pop)

// it's much easier to use __asm__ than to define a bunch of structs
// just to use a single field from them.
// besides, there's at least SOME asm required to get at the GS
// register, so why not do a bit more and save a ton of code?
ptr get_kernel32_modulehandle() {
    ptr modulehandle = 0;
    __asm__ (
        "movq %%gs:0x60, %%rax\n\t"     // rax := PEB
        "movq 0x18(%%rax), %%rax\n\t"   // rax := PEB_LDR_DATA
        "movq 0x20(%%rax), %%rax\n\t"   // rax := InInitializationOrderModuleList
        "movq (%%rax), %%rax\n\t"       // 2nd module (1st is the exe itself)
        "movq (%%rax), %%rax\n\t"       // 3rd module (2nd is ntdll) 
        "movq 0x20(%%rax), %%rax\n\t"   // dllbase for kernel32
        : "=a" (modulehandle)           // return value    
        :                               // no input
        :                               // no clobber
    );
    return modulehandle;
}

// ditto, __asm__ is messy but worth it for this initial part
inline static gpa_PIMAGE_EXPORT_DIRECTORY get_image_exportdirectory(ptr modulehandle) {
    gpa_PIMAGE_EXPORT_DIRECTORY exportdirectory = 0;
    __asm__ (
        "movq %1, %%rcx\n\t"                // rcx := IMAGE_DOS_HEADER
        "movl 0x3c(%%rcx), %%eax\n\t"       // rax := IMAGE_DOS_HEADER->e_lfanew
        "addq %%rcx, %%rax\n\t"             // IMAGE_NT_HEADERS64 := rax
        "leaq 0x18(%%rax), %%rax\n\t"       // rax := IMAGE_OPTIONAL_HEADER64
        "leaq 0x70(%%rax), %%rax\n\t"       // rax := IMAGE_DATA_DIRECTORY
        "leaq 0x00(%%rax), %%rax\n\t"       // rax := IMAGE_DIRECTORY_ENTRY_EXPORT
        "movl 0x00(%%rax), %%edx\n\t"       // edx := IMAGE_DATA_DIRECTORY.VirtualAddress
        "leaq (%%rcx, %%rdx), %%rax\n\t"    // IMAGE_EXPORT_DIRECTORY := modulehandle + edx
        : "=a" (exportdirectory)            // return value
        : "r" (modulehandle)                // input
        : "rdx", "rcx"                      // clobber
    ); 
    return exportdirectory;
}

// since we have no external dependencies, define the only
 // CRT function we need
inline static int gpa_strcmp(char *a, char *b) {
    while (*a && *b && *a == *b) {
        a++;
        b++;
    }
    return *a - *b;
}

// our return type
#ifndef GetProcAddress_t_defined
#define GetProcAddress_t_defined
typedef ptr (*GetProcAddress_t)(ptr modulehandle, char *name);
#endif

// the meat on all the bones
// given a module handle (that can be obtained from get_kernel32_modulehandle))
// return the address of the GetProcAddress function
GetProcAddress_t get_getprocaddress(ptr modulehandle) {
    gpa_PIMAGE_EXPORT_DIRECTORY exportdirectory = get_image_exportdirectory(modulehandle);
    u32 num_names               = exportdirectory->NumberOfNames;
    ptr addressofnames          = exportdirectory->AddressOfNames + modulehandle;
    ptr addressoffunctions      = exportdirectory->AddressOfFunctions + modulehandle;
    ptr addressofnameordinals   = exportdirectory->AddressOfNameOrdinals + modulehandle;
    for (int i = 0; i < num_names; i++) {
        u32 nameoffset = ((u32*)addressofnames)[i];
        u32 ordinal    = ((u16*)addressofnameordinals)[i];
        u32 function   = ((u32*)addressoffunctions)[ordinal];
        char *name     = (char*)(nameoffset + modulehandle);
        if (gpa_strcmp(name, "GetProcAddress") == 0) {
            return function + modulehandle;
        }
    }
    return 0;
}

// just some debug code
#if GETPROCADDRESS_DEBUG
int main (int argc, char *argv[]){
    GetModuleHandleA("kernel32.dll");
    GETPROCADDRESS_DEBUG("kernel32.dll: %p\n", GetModuleHandleA("kernel32.dll"));
    ptr modulehandle = get_kernel32_modulehandle();
    GETPROCADDRESS_DEBUG("modulehandle: %p\n", modulehandle);

    gpa_PIMAGE_EXPORT_DIRECTORY exportdirectory = get_image_exportdirectory(modulehandle);

    u32 num_names               = exportdirectory->NumberOfNames;
    u32 num_functions           = exportdirectory->NumberOfFunctions;
    ptr addressofnames          = exportdirectory->AddressOfNames + modulehandle;
    ptr addressoffunctions      = exportdirectory->AddressOfFunctions + modulehandle;
    ptr addressofnameordinals   = exportdirectory->AddressOfNameOrdinals + modulehandle;

    GETPROCADDRESS_DEBUG("exportdirectory: %p\n",       exportdirectory);
    GETPROCADDRESS_DEBUG("num_names: %d\n",             num_names);
    GETPROCADDRESS_DEBUG("num_functions: %d\n",         num_functions);
    GETPROCADDRESS_DEBUG("addressofnames: %p\n",        addressofnames);
    GETPROCADDRESS_DEBUG("addressoffunctions: %p\n",    addressoffunctions);
    GETPROCADDRESS_DEBUG("addressofnameordinals: %p\n", addressofnameordinals);
    for (int i = 0; i < num_names; i++) {
        u32 nameoffset = ((u32*)addressofnames)[i];
        u32 ordinal    = ((u16*)addressofnameordinals)[i];
        u32 function   = ((u32*)addressoffunctions)[ordinal];
        char *name     = (char*)(nameoffset + modulehandle);
        GETPROCADDRESS_DEBUG("%d: %s: %p\n", i, name, function + modulehandle);
    }
    GETPROCADDRESS_DEBUG("GetProcAddress: %p\n", get_getprocaddress(modulehandle));
    GETPROCADDRESS_DEBUG("GetProcAddress: %p\n", GetProcAddress(modulehandle, "GetProcAddress"));
    return 0;
}
#endif
#endif // _GETPROCADDRESS_C