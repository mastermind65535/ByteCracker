    class PE:
        def __init__(self, BYTES:bytes):
            self.Bytes = bytes(BYTES)
            self.PE_Header = "PE\x00\x00"

        def parse_PE_Header(self):
            pe_signature = self.data[self.e_lfanew:self.e_lfanew + 4].decode()  # "PE\0\0" 확인
            if pe_signature != "PE\x00\x00":
                raise ValueError("유효하지 않은 PE 파일입니다.")

            number_of_sections = self.read_word(self.e_lfanew + 6)  # 섹션 수
            section_table_offset = self.e_lfanew + 0xF8  # 섹션 테이블 시작 위치

            self.sections = []
            for i in range(number_of_sections):
                section_offset = section_table_offset + (i * 40)  # 각 섹션은 40바이트
                section_name = self.data[section_offset:section_offset + 8].decode().strip('\x00')
                virtual_address = self.read_dword(section_offset + 12)
                raw_size = self.read_dword(section_offset + 16)
                raw_data_offset = self.read_dword(section_offset + 20)
                self.sections.append({
                    'name': section_name,
                    'virtual_address': virtual_address,
                    'raw_size': raw_size,
                    'raw_data_offset': raw_data_offset
                })
    
        def getSection(self, section_name:str):
            for section in self.sections:
                if section["name"] == section_name:
                    return section
            return None
    

class ByteCracker:
    class Engine:
        class PE:
            def __init__(self, BYTES:bytes):
                self.BYTES = bytes(BYTES)
                self.
            
            def getDWORD(self, offset:int):
                return int.from_bytes(self.BYTES[offset:offset + 4], byteorder='little')
            
            def getWORD(self, offset:int):
                return int.from_bytes(self.BYTES[offset:offset + 2], byteorder='little')
            
            def getHeader_DOS(self):


            def getHeader_PE(self):
                PE_Sign = self.BYTES[self.]