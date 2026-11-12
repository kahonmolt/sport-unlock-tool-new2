"""Disassemble a Thumb-2 range of the decrypted image."""
import sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CS_OP_IMM, CS_OP_MEM

IMG = r'C:\projects\simagic-evo-sport-modification\tools\Alpha_Evo_Sport_decrypted.bin'
BASE = 0x240
FLASH = 0x08000000
d = open(IMG, 'rb').read()
img = d[BASE:]

def dump(start, end):
    o0 = start - BASE
    o1 = end - BASE
    print('--- 0x%06X..0x%06X (flash 0x%08X) ---' % (start, end, FLASH + o0))
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    for ins in md.disasm(img[o0:o1], FLASH + o0):
        comment = ''
        for op in ins.operands:
            if op.type == CS_OP_IMM and 0x08000000 <= (op.imm & 0xFFFFFFFF) < 0x08030000:
                comment = '   ; -> 0x%08X  (img 0x%06X)' % (op.imm, op.imm - FLASH + BASE)
        print('  %08X  %-8s %-30s%s' % (ins.address, ins.mnemonic, ins.op_str, comment))

for a, b in [(0x14050, 0x14110), (0x22020, 0x22130), (0x26ed0, 0x26f30),
             (0x270f0, 0x27180), (0x17cb0, 0x17e10)]:
    dump(a, b)
    print()
