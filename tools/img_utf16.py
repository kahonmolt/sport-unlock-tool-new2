import struct, re

IMG = r'C:\projects\simagic-evo-sport-modification\tools\Alpha_Evo_Sport_decrypted.bin'
BASE = 0x240
d = open(IMG, 'rb').read()
img = d[BASE:]

# UTF-16LE strings, >= 4 chars, allowing NUL padding runs
print('== UTF-16LE strings (>=4 chars) ==')
res = []
i = 0
while i < len(img) - 8:
    # try to read a run of (printable, 0x00) pairs
    j = i
    s = []
    while j + 1 < len(img) and 0x20 <= img[j] < 0x7F and img[j + 1] == 0:
        s.append(chr(img[j]))
        j += 2
    if len(s) >= 4:
        res.append((i + BASE, ''.join(s)))
        i = j
    else:
        i += 2
for off, s in res:
    print('  0x%06X  %s' % (off, s))
print('total:', len(res))

print('\n== full hexdump 0x28280..0x28600 ==')
for r in range(0x28280 - BASE, 0x28600 - BASE, 16):
    if r >= len(img):
        break
    seg = img[r:r + 16]
    h = seg.hex(' ')
    a = ''.join(chr(c) if 32 <= c < 127 else '.' for c in seg)
    print('  0x%06X  %s  %s' % (r + BASE, h, a))

print('\n== decoded candidate table entries ==')
# look for the pattern <u16 id><u16 0000><utf16 name> at 4-byte alignment
for r in range(0x28280 - BASE, 0x28600 - BASE, 2):
    if r + 4 > len(img):
        break
    b = img[r:r + 2]
    if b[1] == 0x00 and 0x01 <= b[0] <= 0x7F:
        pass
