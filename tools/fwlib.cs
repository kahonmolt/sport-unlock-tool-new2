using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public static class Fw2
{
    public static string Hex(byte[] b, int n)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < n && i < b.Length; i++) sb.Append(b[i].ToString("x2"));
        return sb.ToString();
    }

    public static byte[] Slice(byte[] d, int off, int len)
    {
        var r = new byte[len]; Array.Copy(d, off, r, 0, len); return r;
    }

    public static byte[] Concat(params byte[][] parts)
    {
        int n = 0; foreach (var p in parts) n += p.Length;
        var r = new byte[n]; int o = 0;
        foreach (var p in parts) { Array.Copy(p, 0, r, o, p.Length); o += p.Length; }
        return r;
    }

    public static byte[] Dec(byte[] key, byte[] data, int off, int count, bool cbc, byte[] iv)
    {
        using (var aes = Aes.Create())
        {
            aes.Mode = cbc ? CipherMode.CBC : CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            if (cbc) aes.IV = iv == null ? new byte[16] : iv;
            using (var d = aes.CreateDecryptor()) return d.TransformFinalBlock(data, off, count);
        }
    }

    public static uint LE(byte[] d, int o)
    {
        return (uint)(d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24));
    }

    public static bool Arm(byte[] d)
    {
        if (d.Length < 8) return false;
        uint sp = LE(d, 0), rv = LE(d, 4);
        bool spOk = sp >= 0x20000000 && sp <= 0x20080000 && (sp & 3) == 0;
        bool rvOk = (rv & 1) == 1 && ((rv >= 0x08000000 && rv <= 0x08200000) || (rv >= 0x00000000 && rv <= 0x00040000));
        if (spOk && rvOk) return true;
        // RAM-loaded image: SP 0, reset vector in low range
        if (sp == 0 && (rv & 1) == 1 && rv >= 0x00000000 && rv <= 0x00100000) return true;
        return false;
    }

    // Returns a tag when the first bytes look like a known container or code, else null.
    public static string Magic(byte[] d)
    {
        if (d.Length < 8) return null;
        if (Arm(d)) return "ARM";
        if (d[0] == 0x50 && d[1] == 0x4B && d[2] == 0x03 && d[3] == 0x04) return "ZIP";
        if (d[0] == 0x1F && d[1] == 0x8B) return "GZIP";
        if (d[0] == 0x78 && (d[1] == 0x9C || d[1] == 0x01 || d[1] == 0xDA)) return "ZLIB";
        if (d[0] == 0x7F && d[1] == 0x45 && d[2] == 0x4C && d[3] == 0x46) return "ELF";
        if (d[0] == 0xFD && d[1] == 0x37 && d[2] == 0x7A && d[3] == 0x58 && d[4] == 0x5A) return "XZ";
        if (d[0] == 0x42 && d[1] == 0x5A && d[2] == 0x68) return "BZIP2";
        if (d[0] == 0x37 && d[1] == 0x7A && d[2] == 0xBC && d[3] == 0xAF && d[4] == 0x27 && d[5] == 0x1C) return "7Z";
        int printable = 0;
        for (int i = 0; i < 16; i++) if (d[i] >= 0x20 && d[i] < 0x7F) printable++;
        if (printable == 16) return "ASCII16";
        bool allSame = true;
        for (int i = 1; i < 16; i++) if (d[i] != d[0]) { allSame = false; break; }
        if (allSame) return "CONST";
        // firmware loader hints seen in header
        uint w0 = LE(d, 0);
        if (w0 == 0x0002E780 || w0 == 0x01080000) return "HDRWORD";
        return null;
    }

    public static byte[] Sha256(byte[] d) { using (var h = SHA256.Create()) return h.ComputeHash(d); }
    public static byte[] Sha384(byte[] d) { using (var h = SHA384.Create()) return h.ComputeHash(d); }
    public static byte[] Sha512(byte[] d) { using (var h = SHA512.Create()) return h.ComputeHash(d); }
    public static byte[] Sha1(byte[] d) { using (var h = SHA1.Create()) return h.ComputeHash(d); }
    public static byte[] Md5(byte[] d) { using (var h = MD5.Create()) return h.ComputeHash(d); }
    public static byte[] Hmac(byte[] key, byte[] msg) { using (var h = new HMACSHA256(key)) return h.ComputeHash(msg); }

    public static uint Crc32(byte[] d)
    {
        uint crc = 0xFFFFFFFF;
        for (int i = 0; i < d.Length; i++)
        {
            crc ^= d[i];
            for (int k = 0; k < 8; k++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
        }
        return ~crc;
    }

    public static int IndexOf(byte[] hay, byte[] needle, int start, int end)
    {
        if (needle.Length == 0) return -1;
        for (int i = start; i + needle.Length <= end && i + needle.Length <= hay.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++) if (hay[i + j] != needle[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }

    public static List<byte[]> Ascii16(byte[] f)
    {
        var seen = new HashSet<string>();
        var res = new List<byte[]>();
        for (int i = 0; i + 16 <= f.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < 16; j++) { byte c = f[i + j]; if (c < 0x20 || c > 0x7E) { ok = false; break; } }
            if (!ok) continue;
            var k = new byte[16]; Array.Copy(f, i, k, 0, 16);
            if (seen.Add(Convert.ToBase64String(k))) res.Add(k);
        }
        return res;
    }

    public static List<byte[]> Hex32(byte[] f)
    {
        var seen = new HashSet<string>();
        var res = new List<byte[]>();
        int i = 0;
        while (i < f.Length)
        {
            byte c = f[i];
            bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!isHex) { i++; continue; }
            int start = i;
            while (i < f.Length)
            {
                byte x = f[i];
                if ((x >= '0' && x <= '9') || (x >= 'a' && x <= 'f') || (x >= 'A' && x <= 'F')) i++; else break;
            }
            if (i - start == 32)
            {
                string s = Encoding.ASCII.GetString(f, start, 32);
                var k = new byte[16];
                for (int j = 0; j < 16; j++) k[j] = Convert.ToByte(s.Substring(j * 2, 2), 16);
                if (seen.Add(Convert.ToBase64String(k))) res.Add(k);
            }
            if (i == start) i++;
        }
        return res;
    }

    public static List<byte[]> Base64Keys(byte[] f)
    {
        var seen = new HashSet<string>();
        var res = new List<byte[]>();
        int i = 0;
        while (i < f.Length)
        {
            byte c = f[i];
            bool isB64 = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
            if (!isB64) { i++; continue; }
            int start = i;
            while (i < f.Length)
            {
                byte x = f[i];
                if ((x >= 'A' && x <= 'Z') || (x >= 'a' && x <= 'z') || (x >= '0' && x <= '9') || x == '+' || x == '/' || x == '=') i++; else break;
            }
            int len = i - start;
            if (len >= 22 && len <= 44 && len % 4 == 0)
            {
                try
                {
                    var b = Convert.FromBase64String(Encoding.ASCII.GetString(f, start, len));
                    if (b.Length == 16 && seen.Add(Convert.ToBase64String(b))) res.Add(b);
                }
                catch { }
            }
            if (i == start) i++;
        }
        return res;
    }

    // Test a key against the payload; returns a description when it produces a recognisable plaintext.
    public static string Probe(byte[] key, byte[] cipher)
    {
        var d = Dec(key, cipher, 0, 16, false, null);
        var tag = Magic(d);
        if (tag == null) return null;
        return tag + " " + Hex(d, 16);
    }

    // Raw 16-byte windows over [start, start+len). Returns "offset keyhex tag hex".
    public static List<string> RawSweep(byte[] f, byte[] cipher, int start, int len)
    {
        var hits = new List<string>();
        var key = new byte[16];
        int end = Math.Min(f.Length - 16, start + len);
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            for (int i = Math.Max(0, start); i <= end; i++)
            {
                Array.Copy(f, i, key, 0, 16);
                if (key[0] == 0 && key[1] == 0 && key[2] == 0 && key[3] == 0 &&
                    key[4] == 0 && key[5] == 0 && key[6] == 0 && key[7] == 0) continue;
                aes.Key = key;
                using (var dec = aes.CreateDecryptor())
                {
                    var blk = dec.TransformFinalBlock(cipher, 0, 16);
                    var tag = Magic(blk);
                    if (tag != null) hits.Add(i.ToString("x8") + " " + Hex(key, 16) + " " + tag + " " + Hex(blk, 16));
                }
            }
        }
        return hits;
    }
}

public static class Fw3Extra
{
    public static List<string> RawSweep32(byte[] f, byte[] cipher, int start, int len)
    {
        var hits = new List<string>();
        var key = new byte[32];
        int end = Math.Min(f.Length - 32, start + len);
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            for (int i = Math.Max(0, start); i <= end; i++)
            {
                Array.Copy(f, i, key, 0, 32);
                bool z = true;
                for (int j = 0; j < 8; j++) if (key[j] != 0) { z = false; break; }
                if (z) continue;
                aes.Key = key;
                using (var dec = aes.CreateDecryptor())
                {
                    var blk = dec.TransformFinalBlock(cipher, 0, 16);
                    var tag = Fw2.Magic(blk);
                    if (tag != null) hits.Add(i.ToString("x8") + " " + Fw2.Hex(key, 32) + " " + tag + " " + Fw2.Hex(blk, 16));
                }
            }
        }
        return hits;
    }

    // UTF-16LE ASCII: 16 chars interleaved with zero bytes => 32-byte key (AES-256)
    public static List<byte[]> Utf16Keys(byte[] f)
    {
        var seen = new HashSet<string>();
        var res = new List<byte[]>();
        for (int i = 0; i + 32 <= f.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < 16; j++)
            {
                byte c = f[i + j * 2];
                if (c < 0x20 || c > 0x7E || f[i + j * 2 + 1] != 0) { ok = false; break; }
            }
            if (!ok) continue;
            var k = new byte[32]; Array.Copy(f, i, k, 0, 32);
            if (seen.Add(Convert.ToBase64String(k))) res.Add(k);
        }
        return res;
    }

    public static List<byte[]> Ascii32(byte[] f)
    {
        var seen = new HashSet<string>();
        var res = new List<byte[]>();
        for (int i = 0; i + 32 <= f.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < 32; j++) { byte c = f[i + j]; if (c < 0x20 || c > 0x7E) { ok = false; break; } }
            if (!ok) continue;
            var k = new byte[32]; Array.Copy(f, i, k, 0, 32);
            if (seen.Add(Convert.ToBase64String(k))) res.Add(k);
        }
        return res;
    }
}

public static class Fw4
{
    public static byte[] CtrBlock(byte[] key, byte[] counter)
    {
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            using (var e = aes.CreateEncryptor())
                return e.TransformFinalBlock(counter, 0, 16);
        }
    }

    public static List<string> SweepMask(byte[] f, byte[] cipher, int start, int len, byte mask, bool reverse)
    {
        var hits = new List<string>();
        var key = new byte[16];
        int end = Math.Min(f.Length - 16, start + len);
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None;
            for (int i = Math.Max(0, start); i <= end; i++)
            {
                for (int j = 0; j < 16; j++) key[j] = (byte)(f[i + (reverse ? 15 - j : j)] ^ mask);
                if (key[0] == 0 && key[1] == 0 && key[2] == 0 && key[3] == 0) continue;
                aes.Key = key;
                using (var dec = aes.CreateDecryptor())
                {
                    var blk = dec.TransformFinalBlock(cipher, 0, 16);
                    var tag = Fw2.Magic(blk);
                    if (tag != null) hits.Add(i.ToString("x8") + " mask=" + mask.ToString("x2") + (reverse ? " rev" : "") + " " + Fw2.Hex(key,16) + " " + tag + " " + Fw2.Hex(blk,16));
                }
            }
        }
        return hits;
    }
}
