import pefile
import capstone

class Engine:
    class PE:
        def __init__(self, TARGET:str):
            self.TARGET = str(TARGET)
            self.OBJ_PE = None

        def getPE(self):
            self.OBJ_PE = pefile.PE(self.TARGET)

        def getSection(self, section_name='.text'):
            for section in self.OBJ_PE.sections:
                if section.Name.decode().strip('\x00') == section_name:
                    return section
            return None
        
        def getMachineCode(self):
            text_section = self.getSection()
            if text_section is None:
                raise ValueError("Can't find section: `.text`")

            return text_section.get_data()
        
        def disassemble(self, machine_code:bytes):
            if machine_code is None:
                raise ValueError("기계어 바이트가 없습니다. 먼저 기계어를 추출하세요.")

            # Capstone 디스어셈블러 설정
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)  # 32비트 x86 모드
            disassembly = md.disasm(machine_code, 0x1000)  # 가상의 시작 주소: 0x1000

            # 어셈블리 코드 출력
            for insn in disassembly:
                print(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}")

# 예시 사용법
pe_parser = Engine.PE('target/Elite.exe')  # 분석할 EXE 파일 경로
pe_parser.getPE()

try:
    machine_code = pe_parser.getMachineCode()
    print(f"추출된 기계어 바이트: {machine_code.hex()}")  # 기계어 출력 (앞 64바이트)
    pe_parser.disassemble(machine_code)
except ValueError as e:
    print(e)
