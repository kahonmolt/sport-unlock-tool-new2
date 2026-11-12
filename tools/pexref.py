"""Find all RIP-relative xrefs to given target RVAs in a PE, and show the target string."""
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
from capstone.x86_const import X86_REG_RIP

p = sys.argv[1]
targets = {int(x, 0): None for x in sys.argv[2:]}
pe = pefile.PE(p, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
d = open(p, 'rb').read()
secs = [(s.Name.decode().rstrip('\x00'), s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData)
        for s in pe.sections]

def rva2off(rva):
    for nm, va, ptr, raw in secs:
        if va <= rva < va + raw:
            return ptr + (rva - va)
    return None

def cstr(rva, n=72):
    o = rva2off(rva)
    if o is None:
        return ''
    b = d[o:o + n]
    out = []
    for c in b:
        if 32 <= c < 127:
            out.append(chr(c))
        else:
            break
    return ''.join(out)

text = next(s for s in secs if s[0] == '.text')
nm, va, ptr, raw = text
code = d[ptr:ptr + raw]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.skipdata = True

res = {t: [] for t in targets}
for ins in md.disasm(code, base + va):
    if not ins.id:
        continue
    for op in ins.operands:
        if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
            rv = (ins.address + ins.size + op.mem.disp) - base
            if rv in res:
                res[rv].append((ins.address - base, ins.mnemonic, ins.op_str))

for t in targets:
    print('target 0x%08X  "%s"  (%d xrefs)' % (t, cstr(t), len(res[t])))
    for a, m, o in res[t][:20]:
        print('    0x%08X  %s %s' % (a, m, o))
