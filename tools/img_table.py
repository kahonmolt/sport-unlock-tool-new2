import struct

IMG = r'C:\projects\simagic-evo-sport-modification\tools\Alpha_Evo_Sport_decrypted.bin'
BASE = 0x240
FLASH = 0x08000000
d = open(IMG, 'rb').read()
img = d[BASE:]

def hexdump(off, n):
    for r in range(off, min(off + n, len(img)), 16):
        seg = img[r:r + 16]
        print('  0x%06X  %s  %s' % (r + BASE, seg.hex(' '),
                                    ''.join(chr(c) if 32 <= c < 127 else '.' for c in seg)))

print('== string table start 0x28280..0x28700 (decoded) ==')
r = 0x28280 - BASE
while r < 0x28700 - BASE:
    if r + 2 <= len(img):
        sid = struct.unpack_from('<H', img, r)[0]
        if r + 4 <= len(img) and img[r + 2] != 0 and img[r + 3] == 0 and 0x20 <= img[r + 2] < 0x7f:
            j = r + 2
            s = []
            while j + 1 < len(img) and 0x20 <= img[j] < 0x7F and img[j + 1] == 0:
                s.append(chr(img[j])); j += 2
            if len(s) >= 4:
                print('  id=0x%04X (%d)  @0x%06X  "%s"  next=0x%06X'
                      % (sid, sid, r + 2 + BASE, ''.join(s), j + BASE))
                r = j
                continue
    r += 2

print('\n== xrefs: 32-bit literals pointing into 0x08028200..0x08028700 ==')
lo, hi = FLASH + 0x28200, FLASH + 0x28700
for i in range(0, len(img) - 3, 2):
    v = struct.unpack_from('<I', img, i)[0]
    if lo <= v < hi:
        print('  literal 0x%08X at file 0x%06X (image off 0x%X)' % (v, i + BASE, i))
        hexdump(max(0, i - 16), 48)

print('\n== xrefs: movw/movt immediate pairs for 0x0802xxxx ==')
# Thumb-2 movw rX,#imm16 = F240 0XYZ style; simpler: look for literal pools only above.
# Also report any 32-bit literal in 0x08027000..0x08029000 range.
for i in range(0, len(img) - 3, 2):
    v = struct.unpack_from('<I', img, i)[0]
    if FLASH + 0x27000 <= v < FLASH + 0x29000:
        print('  near-table literal 0x%08X at 0x%06X' % (v, i + BASE))

print('\n== u16 values 0x0310/0x0314/0x0324/0x032C/0x032E/0x0330 elsewhere ==')
for sid in (0x0310, 0x0314, 0x0324, 0x032C, 0x032E, 0x0330):
    pat = struct.pack('<H', sid)
    locs = [i + BASE for i in range(0, len(img) - 1, 2) if img[i:i + 2] == pat]
    print('  0x%04X x%-4d %s' % (sid, len(locs), [hex(x) for x in locs[:12]]))
