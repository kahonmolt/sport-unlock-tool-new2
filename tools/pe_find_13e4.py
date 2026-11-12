"""Locate instructions referencing displacement 0x13e4 (max_torque field) in simpro.exe."""
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

path = r"C:\Program Files (x86)\simpro2\bin\simpro.exe"
pe = pefile.PE(path, fast_load=True)
data = open(path, "rb").read()
secs = [(s.Name.decode().rstrip("\x00"), s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
_, tva, tptr, traw = next(s for s in secs if s[0] == ".text")
code = data[tptr:tptr + traw]

needle = (0x13e4).to_bytes(4, "little")
md = Cs(CS_ARCH_X86, CS_MODE_64)
positions = []
start = 0
while True:
    i = code.find(needle, start)
    if i < 0:
        break
    positions.append(i)
    start = i + 1
print(f"raw occurrences of 0x13e4: {len(positions)}")

seen = set()
for i in positions:
    hit = None
    for back in range(0, 16):
        lo = i - back
        if lo < 0:
            continue
        insns = list(md.disasm(code[lo:lo + 24], tva + lo))
        if not insns:
            continue
        first = insns[0]
        # the instruction must contain the needle position (i is in the disp field)
        if lo <= i < lo + first.size:
            hit = first
            break
    if hit is None:
        print(f"  offset 0x{i:x}: no instruction boundary found")
        continue
    key = (hit.address, hit.mnemonic, hit.op_str)
    if key in seen:
        continue
    seen.add(key)
    print(f"0x{hit.address:08x}  {hit.mnemonic:8s} {hit.op_str}")
