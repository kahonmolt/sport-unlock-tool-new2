"""List builders that start a feature report with a given report ID."""
import re
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP

path = r"C:\Program Files (x86)\simpro2\bin\simpro.exe"
pe = pefile.PE(path, fast_load=True)
data = open(path, "rb").read()
secs = [(s.Name.decode().rstrip("\x00"), s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
_, tva, tptr, traw = next(s for s in secs if s[0] == ".text")
code = data[tptr:tptr + traw]

md = Cs(CS_ARCH_X86, CS_MODE_64)
rid = int(sys.argv[1], 0)
# C6 00 <rid> = mov byte ptr [rax], rid
pat = re.compile(rb"\xc6\x00" + bytes([rid]))
sites = [m.start() for m in pat.finditer(code)]
print(f"builders with report id 0x{rid:02x}: {len(sites)}")
for i in sites:
    rva = tva + i
    # decode the next ~30 instructions
    insns = []
    for insn in md.disasm(code[i:i + 120], rva):
        insns.append(f"{insn.mnemonic} {insn.op_str}")
        if len(insns) >= 12:
            break
    print(f"\n0x{rva:06x}: " + " ; ".join(insns))
