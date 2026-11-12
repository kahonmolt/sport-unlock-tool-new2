#requires -Version 5
$ErrorActionPreference = "Stop"

$SfuSport = "$env:LOCALAPPDATA\SIMAGIC\firmware\base\alpha_evo1\Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu"
$SfuPro   = "$env:LOCALAPPDATA\SIMAGIC\firmware\base\alpha_evo2\Alpha_Evo_Pro_APP-V2.2.3.55-e942d5c2.sfu"
$Exe      = "C:\Program Files (x86)\simpro2\bin\simpro.exe"
$Dll      = "C:\Program Files (x86)\simpro2\bin\simpro_1.dll"

$cs = @'
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public static class Fw
{
    public static string Hex(byte[] b, int n)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < n && i < b.Length; i++) sb.Append(b[i].ToString("x2"));
        return sb.ToString();
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
        return spOk && rvOk;
    }
    public static byte[] Sha256(byte[] d) { using (var h = SHA256.Create()) return h.ComputeHash(d); }
    public static byte[] Md5(byte[] d) { using (var h = MD5.Create()) return h.ComputeHash(d); }
    public static byte[] Hmac(byte[] key, byte[] msg) { using (var h = new HMACSHA256(key)) return h.ComputeHash(msg); }
    public static byte[] Slice(byte[] d, int off, int len) { var r = new byte[len]; Array.Copy(d, off, r, 0, len); return r; }
    public static byte[] Concat(params byte[][] parts)
    {
        int n = 0; foreach (var p in parts) n += p.Length;
        var r = new byte[n]; int o = 0; foreach (var p in parts) { Array.Copy(p, 0, r, o, p.Length); o += p.Length; }
        return r;
    }
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

    // Candidate generation
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
        var sb = new StringBuilder();
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
            int len = i - start;
            if (len == 32)
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
                string s = Encoding.ASCII.GetString(f, start, len);
                try
                {
                    var b = Convert.FromBase64String(s);
                    if (b.Length == 16 && seen.Add(Convert.ToBase64String(b))) res.Add(b);
                }
                catch { }
            }
            if (i == start) i++;
        }
        return res;
    }
    public static List<string> ScanRawWindow(byte[] f, byte[] cipher, int start, int len)
    {
        var hits = new List<string>();
        var key = new byte[16];
        int end = Math.Min(f.Length - 16, start + len);
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            for (int i = start; i <= end; i++)
            {
                Array.Copy(f, i, key, 0, 16);
                if (key[0] == 0 && key[1] == 0 && key[2] == 0 && key[3] == 0 && key[4] == 0 && key[5] == 0 && key[6] == 0 && key[7] == 0) continue;
                aes.Key = key;
                using (var d = aes.CreateDecryptor())
                {
                    var blk = d.TransformFinalBlock(cipher, 0, 16);
                    if (Arm(blk)) hits.Add(i.ToString("x8") + " " + Hex(key, 16) + " " + Hex(blk, 16));
                }
            }
        }
        return hits;
    }
}
'@

Add-Type -TypeDefinition $cs -Language CSharp

$sb = [IO.File]::ReadAllBytes($SfuSport)
$pb = [IO.File]::ReadAllBytes($SfuPro)
$cipher = [Fw]::Slice($sb, 256, $sb.Length - 256)
$hdr = [Fw]::Slice($sb, 0, 256)
$hashBlock = [Fw]::Slice($sb, 0x40, 192)
$zeroIv = New-Object byte[] 16

function Out-Test([string]$label, [byte[]]$key, [byte[]]$iv) {
    $klen = $key.Length * 8
    $ecb = [Fw]::Dec($key, $cipher, 0, 64, $false, $null)
    $cbc = [Fw]::Dec($key, $cipher, 0, 64, $true, $iv)
    $armE = [Fw]::Arm($ecb); $armC = [Fw]::Arm($cbc)
    Write-Output ("{0,-46} AES-{1} | ECB b3={2:x2} arm={3} {4} | CBC b3={5:x2} arm={6} {7}" -f `
        $label, $klen, $ecb[3], $armE, [Fw]::Hex($ecb, 32), $cbc[3], $armC, [Fw]::Hex($cbc, 32))
    return @{ label = $label; klen = $klen; ecb = [Fw]::Hex($ecb, 32); cbc = [Fw]::Hex($cbc, 32); b3 = $ecb[3]; armE = $armE; armC = $armC }
}

$results = New-Object System.Collections.ArrayList
$devA = [Text.Encoding]::ASCII.GetBytes("alpha_evo1")
$verS = [Text.Encoding]::ASCII.GetBytes("2.2.3")
$dev2 = [Text.Encoding]::ASCII.GetBytes("alpha_evo2")
$simagic = [Text.Encoding]::ASCII.GetBytes("simagic")

# A: SHA256(alpha_evo1 + 2.2.3)
$ka = [Fw]::Sha256([Fw]::Concat($devA, $verS))
[void]$results.Add((Out-Test "A SHA256(alpha_evo1+2.2.3) k128" ([Fw]::Slice($ka,0,16)) $zeroIv))
[void]$results.Add((Out-Test "A SHA256(alpha_evo1+2.2.3) k256" $ka $zeroIv))

# C/D: HMAC over payload keyed by device uuid bytes (preset ids, LE 8 repeated)
$uuids = @("3463535048588791808","3463535371365650432","3243493669008838656","3243498132926894080")
foreach ($u in $uuids) {
    $v = [uint64]$u
    $le = [BitConverter]::GetBytes($v)
    $k16 = [Fw]::Concat($le, $le)
    $h = [Fw]::Hmac($k16, $cipher)
    [void]$results.Add((Out-Test ("C HMAC(uuid $u,payload) k128") ([Fw]::Slice($h,0,16)) $zeroIv))
    [void]$results.Add((Out-Test ("C HMAC(uuid $u,payload) k256") $h $zeroIv))
}

# E: SHA256(alpha_evo1 + "00000000")
$ke = [Fw]::Sha256([Fw]::Concat($devA, [Text.Encoding]::ASCII.GetBytes("00000000")))
[void]$results.Add((Out-Test "E SHA256(alpha_evo1+00000000) k128" ([Fw]::Slice($ke,0,16)) $zeroIv))
[void]$results.Add((Out-Test "E SHA256(alpha_evo1+00000000) k256" $ke $zeroIv))

# F: MD5(64-byte header)
$kf = [Fw]::Md5([Fw]::Slice($hdr, 0, 64))
[void]$results.Add((Out-Test "F MD5(header0..63)" $kf $zeroIv))

# G: SHA256(first 32 bytes of payload)
$kg = [Fw]::Sha256([Fw]::Slice($cipher, 0, 32))
[void]$results.Add((Out-Test "G SHA256(payload[0:32]) k128" ([Fw]::Slice($kg,0,16)) $zeroIv))
[void]$results.Add((Out-Test "G SHA256(payload[0:32]) k256" $kg $zeroIv))

# H: nested HMAC
$inner = [Fw]::Hmac($devA, $simagic)
$kh = [Fw]::Hmac($devA, $inner)
[void]$results.Add((Out-Test "H nested HMAC(alpha_evo1) k128" ([Fw]::Slice($kh,0,16)) $zeroIv))
[void]$results.Add((Out-Test "H nested HMAC(alpha_evo1) k256" $kh $zeroIv))

# I: SHA256(device field + version field raw, header)
$ki = [Fw]::Sha256([Fw]::Slice($hdr, 0x10, 32))
[void]$results.Add((Out-Test "I SHA256(hdr 0x10..0x2F) k128" ([Fw]::Slice($ki,0,16)) $zeroIv))
[void]$results.Add((Out-Test "I SHA256(hdr 0x10..0x2F) k256" $ki $zeroIv))

# Extra: BUI key with other IVs and as AES-256
$bui = [Text.Encoding]::ASCII.GetBytes("1@3*5!~8^0#1&34%")
[void]$results.Add((Out-Test "X BUI key, IV=hashBlock[0:16]" $bui ([Fw]::Slice($hashBlock,0,16))))
[void]$results.Add((Out-Test "X BUI key, IV=header 0x30..0x3F" $bui ([Fw]::Slice($hdr,0x30,16))))
[void]$results.Add((Out-Test "X BUI key, IV=hashBlock[176:16]" $bui ([Fw]::Slice($hashBlock,176,16))))
[void]$results.Add((Out-Test "X BUI key x2 as AES-256" ([Fw]::Concat($bui,$bui)) $zeroIv))

Write-Output ""
Write-Output "=== checksum probe: does the 192-byte block 0x40..0xFF contain a digest of the payload? ==="
$sha = [Fw]::Sha256($cipher); $md5 = [Fw]::Md5($cipher); $crc = [Fw]::Crc32($cipher)
Write-Output ("SHA256(payload) = " + [Fw]::Hex($sha, 32))
Write-Output ("MD5(payload)    = " + [Fw]::Hex($md5, 32))
Write-Output ("CRC32(payload)  = {0:x8}" -f $crc)
Write-Output ("SHA256 first16 found in hashBlock at: " + [Fw]::IndexOf($hashBlock, [Fw]::Slice($sha,0,16), 0, 192))
Write-Output ("SHA256 last16  found in hashBlock at: " + [Fw]::IndexOf($hashBlock, [Fw]::Slice($sha,16,16), 0, 192))
Write-Output ("MD5 found in hashBlock at: " + [Fw]::IndexOf($hashBlock, $md5, 0, 192))
$crcB = [BitConverter]::GetBytes($crc)
Write-Output ("CRC32LE found in hashBlock at: " + [Fw]::IndexOf($hashBlock, $crcB, 0, 192))
$allSha = [Fw]::Sha256([Fw]::Concat($hdr, $cipher))
Write-Output ("SHA256(header+payload) first16 in hashBlock at: " + [Fw]::IndexOf($hashBlock, [Fw]::Slice($allSha,0,16), 0, 192))
Write-Output ("hashBlock identical sport/pro: " + ([Fw]::Hex([Fw]::Slice($pb,0x40,192),192) -eq [Fw]::Hex($hashBlock,192)))

$results | ConvertTo-Json -Depth 4 | Set-Content "$env:TEMP\fw_hypotheses.json" -Encoding UTF8
Write-Output ""
Write-Output "=== ASCII-16 candidates in simpro.exe (count) ==="
$exeB = [IO.File]::ReadAllBytes($Exe)
$ascii = [Fw]::Ascii16($exeB)
Write-Output ("count=" + $ascii.Count)
$hits = New-Object System.Collections.ArrayList
$armHits = New-Object System.Collections.ArrayList
foreach ($k in $ascii) {
    $d = [Fw]::Dec($k, $cipher, 0, 16, $false, $null)
    if ($d[3] -eq 0xE7) { [void]$hits.Add([Fw]::Hex($k,16) + " " + [Fw]::Hex($d,16)) }
    if ([Fw]::Arm($d)) { [void]$armHits.Add([Fw]::Hex($k,16) + " " + [Fw]::Hex($d,16)) }
}
Write-Output ("ascii16 b3=0xE7 hits: " + $hits.Count + " ; arm hits: " + $armHits.Count)
$hits | Select-Object -First 10 | ForEach-Object { "  " + $_ }
$armHits | Select-Object -First 10 | ForEach-Object { "  ARM " + $_ }
