#pragma once
#ifndef PE_HEADERS_H
#define PE_HEADERS_H

#include <stdint.h>

#define ___IMAGE_NT_OPTIONAL_HDR32_MAGIC       0x10b
#define ___IMAGE_NT_OPTIONAL_HDR64_MAGIC       0x20b
#define ___IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define ___IMAGE_DOS_SIGNATURE                 0x5A4D

#define ___IMAGE_DIRECTORY_ENTRY_EXPORT          0
#define ___IMAGE_DIRECTORY_ENTRY_IMPORT          1
#define ___IMAGE_DIRECTORY_ENTRY_RESOURCE        2
#define ___IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
#define ___IMAGE_DIRECTORY_ENTRY_SECURITY        4
#define ___IMAGE_DIRECTORY_ENTRY_BASERELOC       5
#define ___IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define ___IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
#define ___IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
#define ___IMAGE_DIRECTORY_ENTRY_TLS             9
#define ___IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define ___IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define ___IMAGE_DIRECTORY_ENTRY_IAT            12
#define ___IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define ___IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

#define ___IMAGE_SIZEOF_SHORT_NAME              8
#define ___IMAGE_SIZEOF_SECTION_HEADER          40

#define __IMAGE_x64_ARCHITECTURE                0x8664  // x64
#define __IMAGE_x86_ARCHITECTURE                0x014C  // x86
#define __IMAGE_ARM_ARCHITECTURE                0x01C0  // ARM
#define __IMAGE_ARM64_ARCHITECTURE              0xAA64  // ARM64
#define __IMAGE_IA64_ARCHITECTURE               0x0200  // Intel Itanium
#define __IMAGE_R3000_ARCHITECTURE              0x0162  // MIPS R3000
#define __IMAGE_R4000_ARCHITECTURE              0x0166  // MIPS R4000
#define __IMAGE_R10000_ARCHITECTURE             0x0168  // MIPS R10000
#define __IMAGE_MIPS16_ARCHITECTURE             0x0266  // MIPS16
#define __IMAGE_ALPHA_ARCHITECTURE              0x0184  // DEC Alpha
#define __IMAGE_POWERPC_ARCHITECTURE            0x01F0  // PowerPC
#define __IMAGE_POWERPCFP_ARCHITECTURE          0x01F1  // PowerPC with floating point support
#define __IMAGE_SH3_ARCHITECTURE                0x01A2  // Hitachi SH3
#define __IMAGE_SH4_ARCHITECTURE                0x01A6  // Hitachi SH4
#define __IMAGE_THUMB_ARCHITECTURE              0x01C2  // ARM Thumb
#define __IMAGE_EBC_ARCHITECTURE                0x0EBC  // EFI Byte Code
#define __IMAGE_M32R_ARCHITECTURE               0x9041  // Mitsubishi M32R
#define __IMAGE_CEF_ARCHITECTURE                0x0CEF  // CEF
#define __IMAGE_AM33_ARCHITECTURE               0x01D3  // Mitsubishi AM33
#define __IMAGE_WCEMIPSV2_ARCHITECTURE          0x0169  // MIPS WCE v2
#define __IMAGE_TRICORE_ARCHITECTURE            0x0520  // Infineon
#define __IMAGE_AMD64_ARCHITECTURE              0x8664  // AMD x64 (Synonym for x64)
#define __IMAGE_ARMNT_ARCHITECTURE              0x01C4  // ARM Thumb-2

std::map<uint16_t, std::string> __WINDOWS_ARCHITECTURES = {
    {__IMAGE_x64_ARCHITECTURE, "x64"},
    {__IMAGE_x86_ARCHITECTURE, "x86"},
    {__IMAGE_ARM_ARCHITECTURE, "ARM"},
    {__IMAGE_ARM64_ARCHITECTURE, "ARM64"},
    {__IMAGE_IA64_ARCHITECTURE, "Itanium"},
    {__IMAGE_POWERPC_ARCHITECTURE, "PowerPC"}
};

struct Windows {
    typedef struct __IMAGE_DOS_HEADER {
        uint16_t e_magic;
        uint16_t e_cblp;
        uint16_t e_cp;
        uint16_t e_crlc;
        uint16_t e_cparhdr;
        uint16_t e_minalloc;
        uint16_t e_maxalloc;
        uint16_t e_ss;
        uint16_t e_sp;
        uint16_t e_csum;
        uint16_t e_ip;
        uint16_t e_cs;
        uint16_t e_lfarlc;
        uint16_t e_ovno;
        uint16_t e_res[4];
        uint16_t e_oemid;
        uint16_t e_oeminfo;
        uint16_t e_res2[10];
        uint32_t e_lfanew;
    } ___IMAGE_DOS_HEADER, * ___PIMAGE_DOS_HEADER;

    typedef struct __IMAGE_DATA_DIRECTORY {
        uint32_t VirtualAddress;
        uint32_t Size;
    } ___IMAGE_DATA_DIRECTORY, * ___PIMAGE_DATA_DIRECTORY;

    typedef struct __IMAGE_OPTIONAL_HEADER {
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint32_t BaseOfData;
        uint32_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint32_t SizeOfStackReserve;
        uint32_t SizeOfStackCommit;
        uint32_t SizeOfHeapReserve;
        uint32_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
        ___IMAGE_DATA_DIRECTORY DataDirectory[___IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } ___IMAGE_OPTIONAL_HEADER32, * ___PIMAGE_OPTIONAL_HEADER32;

    typedef struct __IMAGE_OPTIONAL_HEADER64 {
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint64_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint64_t SizeOfStackReserve;
        uint64_t SizeOfStackCommit;
        uint64_t SizeOfHeapReserve;
        uint64_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
        ___IMAGE_DATA_DIRECTORY DataDirectory[___IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } ___IMAGE_OPTIONAL_HEADER64, * ___PIMAGE_OPTIONAL_HEADER64;

    typedef struct __IMAGE_FILE_HEADER {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
    } ___IMAGE_FILE_HEADER, * ___PIMAGE_FILE_HEADER;

    typedef struct __IMAGE_NT_HEADERS64 {
        uint32_t Signature;
        ___IMAGE_FILE_HEADER FileHeader;
        ___IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } ___IMAGE_NT_HEADERS64, * ___PIMAGE_NT_HEADERS64;

    typedef struct __IMAGE_NT_HEADERS32 {
        uint32_t Signature;
        ___IMAGE_FILE_HEADER FileHeader;
        ___IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } ___IMAGE_NT_HEADERS32, * ___PIMAGE_NT_HEADERS32;

    typedef struct __IMAGE_IMPORT_DESCRIPTOR {
        union {
            uint32_t Characteristics;
            uint32_t OriginalFirstThunk;
        } DUMMYUNIONNAME;
        uint32_t TimeDateStamp;
        uint32_t ForwarderChain;
        uint32_t Name;
        uint32_t FirstThunk;
    } ___IMAGE_IMPORT_DESCRIPTOR, * ___PIMAGE_IMPORT_DESCRIPTOR;

    typedef struct __IMAGE_IMPORT_BY_NAME {
        uint16_t Hint;
        char Name[100];
    } ___IMAGE_IMPORT_BY_NAME, * ___PIMAGE_IMPORT_BY_NAME;

    typedef struct __IMAGE_BASE_RELOCATION {
        uint32_t VirtualAddress;
        uint32_t SizeOfBlock;
    } ___IMAGE_BASE_RELOCATION, * ___PIMAGE_BASE_RELOCATION;

    typedef struct __IMAGE_SECTION_HEADER {
        uint8_t Name[___IMAGE_SIZEOF_SHORT_NAME];
        union {
            uint32_t PhysicalAddress;
            uint32_t VirtualSize;
        } Misc;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
    } ___IMAGE_SECTION_HEADER, * ___PIMAGE_SECTION_HEADER;
};

// Section Characteristics Flags (for Section Header)
#define SECTION_TYPE_REGULAR       0x00000000  // Regular section
#define SECTION_TYPE_CODE          0x00000020  // Code section (executable)
#define SECTION_TYPE_DATA          0x00000040  // Data section (read/write)
#define SECTION_TYPE_BSS           0x00000080  // Uninitialized data section (BSS)
#define SECTION_TYPE_COMDAT        0x00001000  // COMDAT section

#endif // PE_HEADERS_H
