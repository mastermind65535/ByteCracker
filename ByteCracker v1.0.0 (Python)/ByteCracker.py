import json
import capstone
import base64

def disassemble(machine_code: bytes, arch: str, mode: str, start_address: int):
    if not machine_code:
        raise ValueError("기계어 바이트가 없습니다. 먼저 기계어를 추출하세요.")

    # Capstone 설정
    if arch == "x86":
        if mode == "16":
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        elif mode == "32":
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif mode == "64":
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            raise ValueError("x86 아키텍처의 모드는 16, 32, 64 중 하나여야 합니다.")
    elif arch == "x64":
        if mode == "64":
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            raise ValueError("x64 아키텍처는 64 모드만 지원됩니다.")
    else:
        raise ValueError("현재는 x86 또는 x64 아키텍처만 지원됩니다.")

    # 디스어셈블리 수행
    disassembly = md.disasm(machine_code, start_address)

    with open("output.txt", "a") as fp:
        for insn in disassembly:
            print(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}")
            fp.write(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}\n")
        fp.close()


# JSON 데이터 읽기
_target = input("Enter the ByteCracker project file: ")
with open(_target, "r") as fp:
    data = json.load(fp)

# 필요한 정보 추출
optional_header = data["headers"]["__IMAGE_OPTIONAL_HEADER64"]
image_base = optional_header["ImageBase"]
entry_point = optional_header["AddressOfEntryPoint"]

# 시작 주소 계산
start_address = image_base + entry_point
print(f"Calculated Start Address: {start_address:#x}")

# machinecode 변환 (Hexadecimal 문자열을 바이트로 변환)
machine_code = base64.b64decode(data["machinecode"])

# 사용자 입력
arch = data["info"]["architecture"]
mode = input("Enter the mode (16/32/64 for x86, arm/thumb for ARM): ").strip().lower()

# 디스어셈블 수행
disassemble(machine_code, arch, mode, start_address)
