"""
Exhaustive raw-key sweep against the Simagic SFU payload.

For every byte window in a file (sliding, unaligned), treat the window as an
AES-128 or AES-256 key, decrypt the payload blocks starting at 0x100, and test
whether any 16-byte alignment of the result looks like an ARM Cortex-M vector
table (initial SP + reset vector).

Both ECB and CBC-with-IV-zero semantics are covered for block 0 (they are
identical there); a chained (CBC, IV = previous ciphertext block) variant is
also tested, plus every plaintext alignment 0..15.
"""
import sys, time
import numpy as np
import pefile

# ------------------------------------------------------------------ AES core
def _build_tables():
    sbox = np.zeros(256, dtype=np.uint8)
    p = q = 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= q << 1; q ^= q << 2; q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = (q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^
             ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))) & 0xFF
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    inv = np.zeros(256, dtype=np.uint8)
    inv[sbox] = np.arange(256, dtype=np.uint8)
    return sbox, inv

SBOX, INV_SBOX = _build_tables()

def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r

MUL = {n: np.array([_gmul(i, n) for i in range(256)], dtype=np.uint8)
       for n in (9, 11, 13, 14)}

IDX = (np.arange(4)[None, :, None] - np.arange(4)[None, None, :]) % 4

def expand_key(keys, nr):
    n = keys.shape[0]
    nk = keys.shape[1] // 4
    total = 4 * (nr + 1)
    w = np.zeros((n, total, 4), dtype=np.uint8)
    w[:, :nk, :] = keys.reshape(n, nk, 4)
    rcon = 1
    for i in range(nk, total):
        tmp = w[:, i - 1, :].copy()
        if i % nk == 0:
            tmp = SBOX[tmp[:, [1, 2, 3, 0]]]
            tmp[:, 0] ^= np.uint8(rcon)
            rcon = ((rcon << 1) ^ 0x1B) & 0xFF if rcon & 0x80 else (rcon << 1)
        elif nk > 6 and i % nk == 4:
            tmp = SBOX[tmp]
        w[:, i, :] = w[:, i - nk, :] ^ tmp
    return w.reshape(n, nr + 1, 4, 4)

def decrypt_block(rk, ct, nr):
    s = ct.reshape(-1, 4, 4).copy()
    s ^= rk[:, nr]
    for r in range(nr - 1, 0, -1):
        s = np.take_along_axis(s, np.broadcast_to(IDX, s.shape), axis=1)
        s = INV_SBOX[s]
        s ^= rk[:, r]
        b0, b1, b2, b3 = s[:, :, 0], s[:, :, 1], s[:, :, 2], s[:, :, 3]
        s = np.stack([
            MUL[14][b0] ^ MUL[11][b1] ^ MUL[13][b2] ^ MUL[9][b3],
            MUL[9][b0] ^ MUL[14][b1] ^ MUL[11][b2] ^ MUL[13][b3],
            MUL[13][b0] ^ MUL[9][b1] ^ MUL[14][b2] ^ MUL[11][b3],
            MUL[11][b0] ^ MUL[13][b1] ^ MUL[9][b2] ^ MUL[14][b3]], axis=2)
    s = np.take_along_axis(s, np.broadcast_to(IDX, s.shape), axis=1)
    s = INV_SBOX[s]
    s ^= rk[:, 0]
    return s.reshape(-1, 16)

# -------------------------------------------------------------- ARM detection
def arm_mask(win):
    """win: (N,16) uint8 -> bool mask of plausible Cortex-M vector tables."""
    b = win.astype(np.uint32)
    w0 = b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16) | (b[:, 3] << 24)
    sp_ok = ((w0 >= 0x20000000) & (w0 < 0x20100000) & ((w0 & 3) == 0)) | (w0 == 0)
    score = np.zeros(len(win), dtype=np.uint8)
    for k in range(1, 4):
        x = b[:, 4 * k] | (b[:, 4 * k + 1] << 8) | (b[:, 4 * k + 2] << 16) | (b[:, 4 * k + 3] << 24)
        ptr = ((x & 1) == 1) & (((x >= 0x08000000) & (x < 0x08200000)) | (x < 0x00080000))
        score += ptr.astype(np.uint8)
    return sp_ok & (score >= 1)

# --------------------------------------------------------------------- sweep
def _entropy(bs):
    v = np.bincount(np.frombuffer(bytes(bs), dtype=np.uint8), minlength=256).astype(np.float64)
    p = v[v > 0] / len(bs)
    return float(-(p * np.log2(p)).sum())

def verify_key(key_bytes, klen, nr, sfu, start=0x100, length=4096):
    """Decrypt `length` bytes with a single key; return plaintext entropy."""
    k = np.frombuffer(key_bytes, dtype=np.uint8).reshape(1, klen)
    rk = expand_key(k, nr)
    nblk = (length + 15) // 16
    ct = np.frombuffer(sfu[start:start + nblk * 16], dtype=np.uint8).reshape(nblk, 16)
    pt = decrypt_block(rk, ct, nr).reshape(-1)
    return _entropy(pt)

def _report(out, rec, key_bytes, klen, nr, sfu, verbose):
    ent = verify_key(key_bytes, klen, nr, sfu)
    rec = rec + ' entropy=%.3f' % ent
    out.write(rec + '\n')
    if verbose:
        print('HIT', rec, flush=True)
    return ent

def sweep(path, outpath, payload_path, keylens=((16, 10, 'AES-128'), (32, 14, 'AES-256')),
          chunk=150000, verbose=True):
    sfu = open(payload_path, 'rb').read()
    # 64 contiguous ciphertext bytes from 0xF0 to 0x12F: covers windows starting
    # at 0x100+s for s in 0..15 plus the preceding CBC chaining block.
    base = 0xF0
    cstream = np.frombuffer(sfu[base:base + 64], dtype=np.uint8).copy()
    blocks = [base + 16 * i for i in range(4)]          # 0xF0,0x100,0x110,0x120

    try:
        pe = pefile.PE(path, fast_load=True)
        d = open(path, 'rb').read()
        spans = []
        for s in pe.sections:
            nm = s.Name.decode().rstrip('\x00')
            spans.append((nm, s.PointerToRawData, min(s.PointerToRawData + s.SizeOfRawData, len(d))))
    except Exception:
        d = open(path, 'rb').read()
        spans = [('raw', 0, len(d))]

    out = open(outpath, 'w', encoding='utf-8')
    t0 = time.time()
    total = hits = 0
    for klen, nr, label in keylens:
        for nm, a, b in spans:
            pos = a
            while pos + klen <= b:
                m = min(chunk, b - pos - klen + 1)
                arr = np.frombuffer(d, dtype=np.uint8, count=m + klen - 1, offset=pos)
                keys = np.lib.stride_tricks.sliding_window_view(arr, klen)
                rk = expand_key(keys, nr)

                # decrypt blocks 0x100..0x12F (3 blocks) and 0xF0 (chaining ctx)
                cts = np.stack([np.broadcast_to(cstream[o - base:o - base + 16], (m, 16))
                                for o in blocks], axis=1)          # (m,4,16)
                pt = np.stack([decrypt_block(rk, cts[:, i], nr) for i in range(4)], axis=1)
                stream = pt.reshape(m, 64)                        # 0xF0..0x12F

                for s in range(16):                               # plaintext align
                    for blk in (1, 2, 3):                         # 0x100,0x110,0x120
                        off = 16 * blk + s
                        if off + 16 > stream.shape[1]:
                            continue
                        win = stream[:, off:off + 16]
                        msk = arm_mask(win)
                        for j in np.nonzero(msk)[0]:
                            rec = ('%s %s keyoff=0x%x key=%s ctOff=0x%x align=%d pt=%s'
                                   % (label, nm, pos + int(j), bytes(keys[j]).hex(),
                                      base + off, s, bytes(win[j]).hex()))
                            _report(out, rec, bytes(keys[j]), klen, nr, sfu, verbose); hits += 1
                        # CBC variant: xor with preceding ciphertext block
                        prev = cstream[off - 16:off]
                        win2 = win ^ prev
                        msk = arm_mask(win2)
                        for j in np.nonzero(msk)[0]:
                            rec = ('%s %s CBC keyoff=0x%x key=%s ctOff=0x%x align=%d pt=%s'
                                   % (label, nm, pos + int(j), bytes(keys[j]).hex(),
                                      base + off, s, bytes(win2[j]).hex()))
                            _report(out, rec, bytes(keys[j]), klen, nr, sfu, verbose); hits += 1
                total += m
                pos += m
            if verbose:
                print('%s %s done (%.1fs, keys=%d, hits=%d)' % (label, nm, time.time() - t0, total, hits), flush=True)
    out.close()
    print('TOTAL keys=%d hits=%d elapsed=%.1fs' % (total, hits, time.time() - t0))
    return total, hits

if __name__ == '__main__':
    sweep(sys.argv[1], sys.argv[2], sys.argv[3])
