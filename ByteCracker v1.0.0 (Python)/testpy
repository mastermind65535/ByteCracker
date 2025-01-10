import pefile

def extract_functions(file_path):
    pe = pefile.PE(file_path)
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"Library: {entry.dll.decode('utf-8')}")
        for imp in entry.imports:
            print(f"  {imp.name.decode('utf-8') if imp.name else 'Ordinal: ' + str(imp.ordinal)}")

extract_functions("C:\\Users\\maste\\source\\repos\\BloodTear\\BloodTear\\target\\target-x86.exe")
