/* [ SYSTEM COMPONENTS ] */
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <iomanip>
#include <sstream>

/* [ JSON COMPONENTS ] */
#include <nlohmann/json.hpp>

/* [ STRUCTURE COMPONENTS ] */
#include "WindowsStruct.h"

/*
|-------------------------|--------------------------|-----------------------|-----------------------|-----------------------|
[                                             EXECUTABLE FILE STRUCTURE BASED ON OS                                          ]
|-------------------------|--------------------------|-----------------------|-----------------------|-----------------------|
| Operating System        | Windows                  | Linux                 | Android               | iOS                   |
|-------------------------|--------------------------|-----------------------|-----------------------|-----------------------|
| Primary Header Type     | DOS MZ Header            | ELF Header            | ELF Header            | Mach-O Header         |
| Magic Number            | MZ (0x5A4D)              | \x7FELF               | \x7FELF               | 0xfeedface (32-bit)   |
|                         |                          |                       |                       | 0xfeedfacf (64-bit)   |
| Secondary Header Type   | PE Header                | Program Header Table  | DEX                   | Load Commands         |
| Secondary Signature     | PE\0\0                   | None                  | dex\0                 | None                  |
| Extensions              | .exe, .dll               | None, .out, .so       | .dex, .so, .apk       | .app, .dylib, .ipa    |
|-------------------------|--------------------------|-----------------------|-----------------------|-----------------------|



                          | MS-DOS Header            | ELF Header            |                       | Mach-O Header         |
                          |--------------------------|-----------------------|                       |-----------------------|
                          | File Header              | Program Header        |                       | Load Commands         |
                          |                          |                       |                       | Segment Command       |
                          |--------------------------|-----------------------|                       | Segment Sections      |
                          | Optional Header          | Section               |                       |-----------------------|
                          |                          | .interp               |                       | __TEXT Segment        |
                          |--------------------------| .init                 |                       | .text                 |
                          | Section Header           | .plt                  |                       | .cstring              |
                          |                          | .text    Code Section |                       | .literal4             |
                          |                          | .fini                 |                       |-----------------------|
                          |                          | .rodata               |                       | __DATA Segment        |
                          |--------------------------| .data                 |                       | .data                 |
                          | Section                  | .shstrtab             |                       | .bss                  |
                          | .text       Code Section |-----------------------|                       | .rodata               |
                          | .data                    | Section Header        |                       |-----------------------|
                          | .bss                     |                       |                       | __LINKEDIT Segment    |
                          | .rdata                   |                       |                       | .dynsym               |
                          | .idata                   |                       |                       | .dynstr               |
                          | .edata                   |-----------------------|                       | .symtab               |
                          | .reloc                   |                                               [ .strtab               ]
                          | .rsrc                    |                                               [-----------------------]
                          | .pdata                   |                                               [ __TEXT Executable Code]
                          | .tls                     |                                               [ .text                 ]
                          |--------------------------|                                               [ .literal4             ]
                                                                                                     [-----------------------]
                                                                                                     [ Other Segment         ]
                                                                                                     [ .debug                ]
                                                                                                     [ .const                ]
                                                                                                     [ .dtrace               ]
                                                                                                     [-----------------------]



*/

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::vector<uint8_t>& data) {
    std::string encoded;
    int val = 0, valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (encoded.size() % 4) {
        encoded.push_back('=');
    }
    return encoded;
}

class WindowsEngine {
private:
    std::vector<char> DATA;
    std::string TARGET;
    std::string OUTPUT;

public:
    WindowsEngine(std::string filename, std::string output) { TARGET = filename; OUTPUT = output, Init(); }

    int Init() {
        ReadFile();
        if (DATA.data() == nullptr) { std::cout << "[-] File size is nullptr." << std::endl; return 1; }
        Windows::__IMAGE_DOS_HEADER* DOS_Headers = GetDOSHeaders();
        Windows::__IMAGE_FILE_HEADER* File_Headers = GetFileHeaders(DOS_Headers);
        std::string architecture = GetArchitecture(File_Headers);
        if (architecture == "x64") {
            Windows::__IMAGE_NT_HEADERS64* NT64_Headers = GetNT64Headers(DOS_Headers);
            Windows::__IMAGE_SECTION_HEADER* Section_Headers = GetSectionHeaders(NT64_Headers);
            Windows::__IMAGE_SECTION_HEADER* CodeSection = GetSection(NT64_Headers, Section_Headers, ".text");

            std::vector<uint8_t> RAW_MACHINE_CODE(DATA.begin() + CodeSection->PointerToRawData, DATA.begin() + CodeSection->PointerToRawData + CodeSection->SizeOfRawData);
            std::string MACHINE_CODE = base64_encode(RAW_MACHINE_CODE);

            x64export(DOS_Headers, File_Headers, NT64_Headers, Section_Headers, MACHINE_CODE, OUTPUT);
        }
        return 0;
    }

    int ReadFile() {
        std::ifstream FileReader(TARGET, std::ios::binary);
        if (!FileReader) { return 1; }

        FileReader.seekg(0, std::ios::end);
        std::streamsize FILE_SIZE = FileReader.tellg();
        FileReader.seekg(0, std::ios::beg);

        DATA.resize(FILE_SIZE);
        FileReader.read(DATA.data(), FILE_SIZE);

        FileReader.close();
        return 0;
    }

    Windows::__IMAGE_DOS_HEADER* GetDOSHeaders() { return  reinterpret_cast<Windows::__IMAGE_DOS_HEADER*>(DATA.data()); }
    Windows::__IMAGE_FILE_HEADER* GetFileHeaders(Windows::__IMAGE_DOS_HEADER* DOS_Headers) { return reinterpret_cast<Windows::__IMAGE_FILE_HEADER*>(DATA.data() + DOS_Headers->e_lfanew + sizeof(uint32_t)); }

    Windows::__IMAGE_NT_HEADERS64* GetNT64Headers(Windows::__IMAGE_DOS_HEADER* DOS_Headers) { return reinterpret_cast<Windows::__IMAGE_NT_HEADERS64*>(DATA.data() + DOS_Headers->e_lfanew); }
    Windows::__IMAGE_NT_HEADERS32* GetNT32Headers(Windows::__IMAGE_DOS_HEADER* DOS_Headers) { return reinterpret_cast<Windows::__IMAGE_NT_HEADERS32*>(DATA.data() + DOS_Headers->e_lfanew); }

    Windows::__IMAGE_SECTION_HEADER* GetSectionHeaders(Windows::__IMAGE_NT_HEADERS32* ntHeaders) {
        return reinterpret_cast<Windows::__IMAGE_SECTION_HEADER*>(reinterpret_cast<uint8_t*>(&ntHeaders->OptionalHeader) + ntHeaders->FileHeader.SizeOfOptionalHeader);
    }
    Windows::__IMAGE_SECTION_HEADER* GetSectionHeaders(Windows::__IMAGE_NT_HEADERS64* ntHeaders) {
        return reinterpret_cast<Windows::__IMAGE_SECTION_HEADER*>(reinterpret_cast<uint8_t*>(&ntHeaders->OptionalHeader) + ntHeaders->FileHeader.SizeOfOptionalHeader);
    }

    Windows::__IMAGE_SECTION_HEADER* GetSection(Windows::__IMAGE_NT_HEADERS64* ntHeaders, Windows::__IMAGE_SECTION_HEADER* Section_Headers, std::string SECTION_NAME) {
        Windows::__IMAGE_SECTION_HEADER* Section = nullptr;
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            if (strncmp(reinterpret_cast<const char*>(Section_Headers[i].Name), SECTION_NAME.c_str(), SECTION_NAME.size()) == 0) {
                Section = &Section_Headers[i];
                break;
            }
        }
        return Section;
    }

    Windows::__IMAGE_SECTION_HEADER* GetSection(Windows::__IMAGE_NT_HEADERS32* ntHeaders, Windows::__IMAGE_SECTION_HEADER* Section_Headers, std::string SECTION_NAME) {
        Windows::__IMAGE_SECTION_HEADER* Section = nullptr;
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            if (strncmp(reinterpret_cast<const char*>(Section_Headers[i].Name), SECTION_NAME.c_str(), SECTION_NAME.size()) == 0) {
                Section = &Section_Headers[i];
                break;
            }
        }
        return Section;
    }

    std::string GetArchitecture(Windows::__IMAGE_FILE_HEADER* File_Headers) {
        if (__WINDOWS_ARCHITECTURES.count(File_Headers->Machine) > 0) { return __WINDOWS_ARCHITECTURES[File_Headers->Machine]; }
        else { return "Unknown"; }
    }

    void x64export(
        Windows::__IMAGE_DOS_HEADER* DOS_Headers,
        Windows::__IMAGE_FILE_HEADER* File_Headers,
        Windows::__IMAGE_NT_HEADERS64* NT64_Headers,
        Windows::__IMAGE_SECTION_HEADER* Section_Headers,
        std::string MACHINE_CODE,
        std::string output
        ) {
        nlohmann::json outputJson;

        outputJson["info"]["target"] = TARGET;
        outputJson["info"]["size"] = DATA.size();
        outputJson["info"]["architecture"] = GetArchitecture(File_Headers);

        outputJson["headers"]["__IMAGE_DOS_HEADER"] = {
            {"e_magic", DOS_Headers->e_magic},
            {"e_cblp", DOS_Headers->e_cblp},
            {"e_cp", DOS_Headers->e_cp},
            {"e_crlc", DOS_Headers->e_crlc},
            {"e_cparhdr", DOS_Headers->e_cparhdr},
            {"e_minalloc", DOS_Headers->e_minalloc},
            {"e_maxalloc", DOS_Headers->e_maxalloc},
            {"e_ss", DOS_Headers->e_ss},
            {"e_sp", DOS_Headers->e_sp},
            {"e_csum", DOS_Headers->e_csum},
            {"e_ip", DOS_Headers->e_ip},
            {"e_cs", DOS_Headers->e_cs},
            {"e_lfarlc", DOS_Headers->e_lfarlc},
            {"e_ovno", DOS_Headers->e_ovno},
            {"e_oemid", DOS_Headers->e_oemid},
            {"e_oeminfo", DOS_Headers->e_oeminfo},
            {"e_lfanew", DOS_Headers->e_lfanew}
        };

        outputJson["headers"]["__IMAGE_NT_HEADERS64"] = {
            {"Signature", NT64_Headers->Signature},
        };

        outputJson["headers"]["__IMAGE_FILE_HEADER"] = {
            {"Machine", File_Headers->Machine},
            {"NumberOfSections", File_Headers->NumberOfSections},
            {"TimeDateStamp", File_Headers->TimeDateStamp},
            {"PointerToSymbolTable", File_Headers->PointerToSymbolTable},
            {"NumberOfSymbols", File_Headers->NumberOfSymbols},
            {"SizeOfOptionalHeader", File_Headers->SizeOfOptionalHeader},
            {"Characteristics", File_Headers->Characteristics}
        };

        outputJson["headers"]["__IMAGE_OPTIONAL_HEADER64"] = {
            {"Magic", NT64_Headers->OptionalHeader.Magic},
            {"MajorLinkerVersion", NT64_Headers->OptionalHeader.MajorLinkerVersion},
            {"MinorLinkerVersion", NT64_Headers->OptionalHeader.MinorLinkerVersion},
            {"SizeOfCode", NT64_Headers->OptionalHeader.SizeOfCode},
            {"SizeOfInitializedData", NT64_Headers->OptionalHeader.SizeOfInitializedData},
            {"SizeOfUninitializedData", NT64_Headers->OptionalHeader.SizeOfUninitializedData},
            {"AddressOfEntryPoint", NT64_Headers->OptionalHeader.AddressOfEntryPoint},
            {"BaseOfCode", NT64_Headers->OptionalHeader.BaseOfCode},
            {"ImageBase", NT64_Headers->OptionalHeader.ImageBase},
            {"SectionAlignment", NT64_Headers->OptionalHeader.SectionAlignment},
            {"FileAlignment", NT64_Headers->OptionalHeader.FileAlignment},
            {"MajorOperatingSystemVersion", NT64_Headers->OptionalHeader.MajorOperatingSystemVersion},
            {"MinorOperatingSystemVersion", NT64_Headers->OptionalHeader.MinorOperatingSystemVersion},
            {"MajorImageVersion", NT64_Headers->OptionalHeader.MajorImageVersion},
            {"MinorImageVersion", NT64_Headers->OptionalHeader.MinorImageVersion},
            {"MajorSubsystemVersion", NT64_Headers->OptionalHeader.MajorSubsystemVersion},
            {"MinorSubsystemVersion", NT64_Headers->OptionalHeader.MinorSubsystemVersion},
            {"Win32VersionValue", NT64_Headers->OptionalHeader.Win32VersionValue},
            {"SizeOfImage", NT64_Headers->OptionalHeader.SizeOfImage},
            {"SizeOfHeaders", NT64_Headers->OptionalHeader.SizeOfHeaders},
            {"CheckSum", NT64_Headers->OptionalHeader.CheckSum},
            {"Subsystem", NT64_Headers->OptionalHeader.Subsystem},
            {"DllCharacteristics", NT64_Headers->OptionalHeader.DllCharacteristics},
            {"SizeOfStackReserve", NT64_Headers->OptionalHeader.SizeOfStackReserve},
            {"SizeOfStackCommit", NT64_Headers->OptionalHeader.SizeOfStackCommit},
            {"SizeOfHeapReserve", NT64_Headers->OptionalHeader.SizeOfHeapReserve},
            {"SizeOfHeapCommit", NT64_Headers->OptionalHeader.SizeOfHeapCommit},
            {"LoaderFlags", NT64_Headers->OptionalHeader.LoaderFlags},
            {"NumberOfRvaAndSizes", NT64_Headers->OptionalHeader.NumberOfRvaAndSizes}
        };

        outputJson["headers"]["__IMAGE_SECTION_HEADER"] = {
            {"Name", Section_Headers->Name},
            {"VirtualSize", Section_Headers->Misc.PhysicalAddress},
            {"VirtualSize", Section_Headers->Misc.VirtualSize},
            {"VirtualAddress", Section_Headers->VirtualAddress},
            {"SizeOfRawData", Section_Headers->SizeOfRawData},
            {"PointerToRawData", Section_Headers->PointerToRawData},
            {"PointerToRelocations", Section_Headers->PointerToRelocations},
            {"PointerToLinenumbers", Section_Headers->PointerToLinenumbers},
            {"NumberOfRelocations", Section_Headers->NumberOfRelocations},
            {"NumberOfLinenumbers", Section_Headers->NumberOfLinenumbers},
            {"Characteristics", Section_Headers->Characteristics}
        };

        outputJson["machinecode"] = MACHINE_CODE;
        outputJson["assembly"] = "";

        std::ofstream outputFile(output);
        if (outputFile.is_open()) {
            outputFile << std::setw(4) << outputJson << std::endl;
            outputFile.close();
            std::cout << "EXPORT=" << output << std::endl;
        }
        else {
            std::cerr << "Failed." << std::endl;
        }
    }

    void x86export(
        Windows::__IMAGE_DOS_HEADER* DOS_Headers,
        Windows::__IMAGE_FILE_HEADER* File_Headers,
        Windows::__IMAGE_NT_HEADERS32* NT32_Headers,
        Windows::__IMAGE_SECTION_HEADER* Section_Headers,
        std::string MACHINE_CODE,
        std::string output
    ) {

    }
};

int main(int argc, char* argv[]) {
    std::vector<std::string> args(argv, argv + argc);
    WindowsEngine WinEngine(args[1], args[2]);
}