#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

#include <string>
#include <cstdint>
#include <vector>
#include <sstream>
#include <iomanip>
#include <map>

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

using json = nlohmann::json;
using namespace std;

std::map<uint16_t, std::string> ARCHITECTURES = {
    {__IMAGE_x64_ARCHITECTURE, "x64"},
    {__IMAGE_x86_ARCHITECTURE, "x86"},
    {__IMAGE_ARM_ARCHITECTURE, "ARM"},
    {__IMAGE_ARM64_ARCHITECTURE, "ARM64"},
    {__IMAGE_IA64_ARCHITECTURE, "Itanium"},
    {__IMAGE_POWERPC_ARCHITECTURE, "PowerPC"}
};

struct PEHeaders {
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

class ByteCracker {
public:
    class Engine {
    public:
        class PE {
        private:
            string TARGET;
            vector<char> DATA;
            string HEX_STRING;
            PEHeaders::__IMAGE_DOS_HEADER* DOS_Headers;
            PEHeaders::__IMAGE_FILE_HEADER* File_Headers;
            PEHeaders::__IMAGE_NT_HEADERS64* NT64_Headers;
            PEHeaders::__IMAGE_NT_HEADERS32* NT32_Headers;
            PEHeaders::__IMAGE_SECTION_HEADER* Section_Headers;

        public:
            PE(std::string filename) {
                TARGET = filename;

                Init();
            }

            int Init() {
                if (int result = ReadFile()) return result;
                if (int result = GetDOSHeaders()) return result;
                if (int result = GetFileHeaders()) return result;
                if (GetArchitecture() == "x64") {
                    if (int result = GetNT64Headers()) return result;
                    if (int result = GetSectionHeaders(NT64_Headers)) return result;
                    PEHeaders::__IMAGE_SECTION_HEADER* textSection = GetSection(NT64_Headers, ".text");
                    size_t textOffset = textSection->PointerToRawData;
                    size_t textSize = textSection->SizeOfRawData;

                    if (textOffset + textSize > DATA.size()) {
                        std::cerr << "Invalid .text section size or offset." << std::endl;
                        return 6;
                    }

                    std::vector<uint8_t> textData(DATA.begin() + textOffset, DATA.begin() + textOffset + textSize);

                    HEX_STRING = BytesToHexString(textData);
                }
            }

            int ReadFile() {
                /* Object Initialization */
                ifstream FileReader(TARGET, ios::binary);       // Read 'Target' as binary mode (ios::binary)
                if (!FileReader) { return 1; }                  // Error Code 1 => File read failed

                /* File Size Calculation */
                FileReader.seekg(0, ios::end);                  // Move pointer to the end (ios::end)
                streamsize FileSize = FileReader.tellg();       // Measure file size
                FileReader.seekg(0, ios::beg);                  // Move pointer to the first (ios::beg)

                /* File Read */
                DATA.resize(FileSize);                          // Prepare vector for file reading (Memory pre allocation)
                FileReader.read(DATA.data(), FileSize);         // Read the target file
                
                FileReader.close();                             // Close file reader
                return 0;                                       // Success Code 0
            }

            int GetDOSHeaders() {
                /* [ DOS HEADER PARSING ] */
                DOS_Headers = reinterpret_cast<PEHeaders::__IMAGE_DOS_HEADER*>(DATA.data());            // Load all headers
                if (DOS_Headers->e_magic != ___IMAGE_DOS_SIGNATURE) { return 2; }                       // Error Code 2 => File does not contain 0x5A4D (MZ) magic number
                return 0;                                                                               // Success Code 0
            }

            int GetFileHeaders() {
                /* [ FILE HEADER PARSING ] */
                size_t coffHeaderOffset = DOS_Headers->e_lfanew + sizeof(uint32_t);                                 // e_lfanew points to PE signature (4 bytes), skip it
                File_Headers = reinterpret_cast<PEHeaders::__IMAGE_FILE_HEADER*>(DATA.data() + coffHeaderOffset);   // Loaad all headers
                if (File_Headers->Machine != 0x14c && File_Headers->Machine != 0x8664) { return 3; }                // Error Code 3 => Unsupported architecture
                return 0;
            }

            int GetNT64Headers() {
               /* [ NT32 HEADER PARSING ] */
                NT64_Headers = reinterpret_cast<PEHeaders::__IMAGE_NT_HEADERS64*>(DATA.data() + DOS_Headers->e_lfanew);
                return 0;
            }

            int GetNT32Headers() {
                /* [ NT64 HEADER PARSING ] */
                NT32_Headers = reinterpret_cast<PEHeaders::__IMAGE_NT_HEADERS32*>(DATA.data() + DOS_Headers->e_lfanew);
                return 0;
            }

            int GetSectionHeaders(PEHeaders::__IMAGE_NT_HEADERS32* ntHeaders) {
                Section_Headers = reinterpret_cast<PEHeaders::__IMAGE_SECTION_HEADER*>(
                    reinterpret_cast<uint8_t*>(&ntHeaders->OptionalHeader) + ntHeaders->FileHeader.SizeOfOptionalHeader);
                return 0;
            }

            int GetSectionHeaders(PEHeaders::__IMAGE_NT_HEADERS64* ntHeaders) {
                Section_Headers = reinterpret_cast<PEHeaders::__IMAGE_SECTION_HEADER*>(
                    reinterpret_cast<uint8_t*>(&ntHeaders->OptionalHeader) + ntHeaders->FileHeader.SizeOfOptionalHeader);
                return 0;
            }

            PEHeaders::__IMAGE_SECTION_HEADER* GetSection(PEHeaders::__IMAGE_NT_HEADERS64* ntHeaders, std::string SECTION_NAME) {
                PEHeaders::__IMAGE_SECTION_HEADER* Section = nullptr;
                for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
                    if (strncmp(reinterpret_cast<const char*>(Section_Headers[i].Name), SECTION_NAME.c_str(), SECTION_NAME.size()) == 0) {
                        Section = &Section_Headers[i];
                        break;
                    }
                }
                return Section;
            }

            PEHeaders::__IMAGE_SECTION_HEADER* GetSection(PEHeaders::__IMAGE_NT_HEADERS32* ntHeaders, std::string SECTION_NAME) {
                PEHeaders::__IMAGE_SECTION_HEADER* Section = nullptr;
                for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
                    if (strncmp(reinterpret_cast<const char*>(Section_Headers[i].Name), SECTION_NAME.c_str(), SECTION_NAME.size()) == 0) {
                        Section = &Section_Headers[i];
                        break;
                    }
                }
                return Section;
            }

            string GetArchitecture() {
                if (ARCHITECTURES.count(File_Headers->Machine) > 0) { return ARCHITECTURES[File_Headers->Machine]; }
                else { return "Unknown"; }
            }

            std::string BytesToHexString(const std::vector<uint8_t>& data) {
                std::ostringstream oss;
                for (size_t i = 0; i < data.size(); ++i) {
                    oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
                }
                return oss.str();
            }

            void PrintDOS() {
                cout << "[__IMAGE_DOS_HEADER]" << endl;
                cout << "e_magic=" << DOS_Headers->e_magic << endl;
                cout << "e_cblp=" << DOS_Headers->e_cblp << endl;
                cout << "e_cp=" << DOS_Headers->e_cp << endl;
                cout << "e_crlc=" << DOS_Headers->e_crlc << endl;
                cout << "e_cparhdr=" << DOS_Headers->e_cparhdr << endl;
                cout << "e_minalloc=" << DOS_Headers->e_minalloc << endl;
                cout << "e_maxalloc=" << DOS_Headers->e_maxalloc << endl;
                cout << "e_ss=" << DOS_Headers->e_ss << endl;
                cout << "e_sp=" << DOS_Headers->e_sp << endl;
                cout << "e_csum=" << DOS_Headers->e_csum << endl;
                cout << "e_ip=" << DOS_Headers->e_ip << endl;
                cout << "e_cs=" << DOS_Headers->e_cs << endl;
                cout << "e_lfarlc=" << DOS_Headers->e_lfarlc << endl;
                cout << "e_ovno=" << DOS_Headers->e_ovno << endl;

                cout << "e_oemid=" << DOS_Headers->e_oemid << endl;
                cout << "e_oeminfo=" << DOS_Headers->e_oeminfo << endl;

                cout << "e_lfanew=" << DOS_Headers->e_lfanew << dec << endl;

                cout << "[END]" << endl;
            }

            void PrintFile() {
                cout << "[__IMAGE_FILE_HEADER]" << endl;
                cout << "Machine=" << File_Headers->Machine << endl;
                cout << "NumberOfSections=" << File_Headers->NumberOfSections << endl;
                cout << "TimeDateStamp=" << File_Headers->TimeDateStamp << endl;
                cout << "PointerToSymbolTable=" << File_Headers->PointerToSymbolTable << endl;
                cout << "NumberOfSymbols=" << File_Headers->NumberOfSymbols << endl;
                cout << "SizeOfOptionalHeader=" << File_Headers->SizeOfOptionalHeader << endl;
                cout << "Characteristics=" << File_Headers->Characteristics << dec << endl;
                cout << "[END]" << endl;
            }

            void makeReport(const string& output) {
                json outputJson;

                outputJson["headers"]["DOS"] = {
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

                outputJson["headers"]["File"] = {
                    {"Machine", File_Headers->Machine},
                    {"NumberOfSections", File_Headers->NumberOfSections},
                    {"TimeDateStamp", File_Headers->TimeDateStamp},
                    {"PointerToSymbolTable", File_Headers->PointerToSymbolTable},
                    {"NumberOfSymbols", File_Headers->NumberOfSymbols},
                    {"SizeOfOptionalHeader", File_Headers->SizeOfOptionalHeader},
                    {"Characteristics", File_Headers->Characteristics}
                };

                outputJson["machinecode"] = HEX_STRING;
                outputJson["assembly"] = json::array();

                ofstream outputFile(output);
                if (outputFile.is_open()) {
                    outputFile << std::setw(4) << outputJson << endl;
                    outputFile.close();
                    cout << "[+] REPORT_PATH=" << output << endl;
                }
                else {
                    cerr << "[-] REPORT FAILED" << endl;
                }
            }
        };
    };
};

int main(int argc, char* argv[])
{
    std::vector<std::string> args(argv, argv + argc);
    ByteCracker::Engine::PE PE_Engine(args[1]);
    PE_Engine.makeReport(args[2]);
}