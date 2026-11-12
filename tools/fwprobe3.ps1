#requires -Version 5
$ErrorActionPreference = "Stop"
Add-Type -Path "C:\projects\simagic-evo-sport-modification\tools\fwlib.cs"
$W = [Console]::Out
$SfuSport = "$env:LOCALAPPDATA\SIMAGIC\firmware\base\alpha_evo1\Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu"
$Exe = "C:\Program Files (x86)\simpro2\bin\simpro.exe"
$sb = [IO.File]::ReadAllBytes($SfuSport)
$cipher = [Fw2]::Slice($sb, 256, $sb.Length - 256)
$hdrF = [Fw2]::Slice($sb, 0x30, 16)
$hashBlock = [Fw2]::Slice($sb, 0x40, 192)
$zero = New-Object byte[] 16

function Probe([string]$label, [byte[]]$key, [byte[]]$data, [byte[]]$iv, [bool]$cbc) {
    $d = [Fw2]::Dec($key, $data, 0, 16, $cbc, $iv)
    $tag = [Fw2]::Magic($d); if (-not $tag) { $tag = "-" }
    $W.WriteLine(("{0,-40} AES-{1} {2} tag={3} {4}" -f $label, ($key.Length*8), ($(if($cbc){"CBC"}else{"ECB"})), $tag, [Fw2]::Hex($d,16)))
}

$W.WriteLine("=== derived / header-material keys ===")
Probe "key=header 0x30..0x3F (16B)" $hdrF $cipher $zero $false
Probe "key=header 0x30..0x3F CBC0" $hdrF $cipher $zero $true
Probe "key=hashBlock[0:16]" ([Fw2]::Slice($hashBlock,0,16)) $cipher $zero $false
Probe "key=SHA256(hdr 0x30..0x3F) k128" ([Fw2]::Slice([Fw2]::Sha256($hdrF),0,16)) $cipher $zero $false
Probe "key=SHA256(hdr 0x30..0x3F) k256" ([Fw2]::Sha256($hdrF)) $cipher $zero $false
Probe "key=SHA256(hashBlock) k128" ([Fw2]::Slice([Fw2]::Sha256($hashBlock),0,16)) $cipher $zero $false
Probe "key=SHA256(hashBlock) k256" ([Fw2]::Sha256($hashBlock)) $cipher $zero $false
Probe "key=MD5(hashBlock)" ([Fw2]::Md5($hashBlock)) $cipher $zero $false
$bui = [Text.Encoding]::ASCII.GetBytes("1@3*5!~8^0#1&34%")
Probe "key=MD5(BUI key)" ([Fw2]::Md5($bui)) $cipher $zero $false
Probe "key=SHA256(BUI key) k128" ([Fw2]::Slice([Fw2]::Sha256($bui),0,16)) $cipher $zero $false
Probe "key=rev(BUI key)" ([byte[]]($bui[15..0])) $cipher $zero $false
Probe "key=BUI key xor 0xFF" ([byte[]]($bui | ForEach-Object { $_ -bxor 0xFF })) $cipher $zero $false

$W.WriteLine("")
$W.WriteLine("=== BUI key with IV-prefixed ciphertext (cipher[0:16] as IV, data from 16) ===")
Probe "BUI IV=cipher[0:16], data+16" $bui ([Fw2]::Slice($cipher,16,$cipher.Length-16)) ([Fw2]::Slice($cipher,0,16)) $true

$W.WriteLine("")
$W.WriteLine("=== decompression attempts on the raw payload (no key) ===")
function TryInflate([string]$label, [byte[]]$data, [int]$skip) {
    try {
        $ms = New-Object IO.MemoryStream(,$data)
        if ($skip -gt 0) { [void]$ms.Seek($skip, 'Begin') }
        $ds = New-Object IO.Compression.DeflateStream($ms, [IO.Compression.CompressionMode]::Decompress)
        $buf = New-Object byte[] 4096
        $n = $ds.Read($buf, 0, $buf.Length)
        $hx = ($buf[0..([Math]::Min(31,$n-1))] | ForEach-Object { $_.ToString('x2') }) -join ' '
        $W.WriteLine(("{0}: READ {1} bytes, head={2}" -f $label, $n, $hx))
        $ds.Dispose()
    } catch {
        $W.WriteLine(("{0}: FAILED {1}" -f $label, $_.Exception.Message.Split([char]10)[0]))
    }
}
TryInflate "raw deflate" $cipher 0
TryInflate "deflate skipping 2" $cipher 2
try { $ms = New-Object IO.MemoryStream(,$cipher); $gz = New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress); $b = New-Object byte[] 64; $n = $gz.Read($b,0,64); $W.WriteLine("gzip: READ $n"); $gz.Dispose() } catch { $W.WriteLine("gzip: FAILED " + $_.Exception.Message.Split([char]10)[0]) }

$W.WriteLine("")
$W.WriteLine("=== structure checks ===")
$seen = New-Object 'System.Collections.Generic.HashSet[string]'
$dups = 0
for ($i = 0; $i -lt $cipher.Length; $i += 16) {
    $b = [Fw2]::Slice($cipher, $i, 16)
    if (-not $seen.Add([Convert]::ToBase64String($b))) { $dups++ }
}
$W.WriteLine("payload 16-byte block duplicates: $dups of $($cipher.Length/16)")
$hb = $hashBlock
$freq = @{}; foreach ($x in $hb) { if ($freq.ContainsKey($x)) { $freq[$x]++ } else { $freq[$x] = 1 } }
$ent = 0.0; foreach ($k in $freq.Keys) { $p = $freq[$k]/$hb.Length; $ent -= $p*[Math]::Log($p,2) }
$W.WriteLine(("hash block entropy={0:N3} distinct={1}" -f $ent, $freq.Count))
$W.WriteLine("hash block as 6 x 32 bytes:")
for ($i = 0; $i -lt 192; $i += 32) { $W.WriteLine("  [" + ($i/32) + "] " + [Fw2]::Hex([Fw2]::Slice($hb,$i,32),32)) }

$W.WriteLine("")
$W.WriteLine("=== 32-byte key sweeps (AES-256) ===")
$exeB = [IO.File]::ReadAllBytes($Exe)
$a32 = [Fw3Extra]::Ascii32($exeB)
$u16 = [Fw3Extra]::Utf16Keys($exeB)
$W.WriteLine("ascii32=$($a32.Count) utf16-ascii-16=$($u16.Count)")
$hits = 0
foreach ($k in $a32) { $tag = [Fw2]::Probe($k, $cipher); if ($tag) { $W.WriteLine("  HIT ascii32 " + [Fw2]::Hex($k,32) + " " + $tag); $hits++ } }
foreach ($k in $u16) { $tag = [Fw2]::Probe($k, $cipher); if ($tag) { $W.WriteLine("  HIT utf16 " + [Fw2]::Hex($k,32) + " " + $tag); $hits++ } }
$W.WriteLine("candidate hits=$hits")
$sw = [Diagnostics.Stopwatch]::StartNew()
$raw32 = [Fw3Extra]::RawSweep32($exeB, $cipher, 0, $exeB.Length)
$sw.Stop()
$W.WriteLine(("raw32 windows={0} {1:N1}s hits={2}" -f ($exeB.Length-32), $sw.Elapsed.TotalSeconds, $raw32.Count))
$raw32 | Select-Object -First 10 | ForEach-Object { "  RAW32 " + $_ }
