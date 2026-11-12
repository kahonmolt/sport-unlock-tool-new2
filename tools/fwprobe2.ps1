#requires -Version 5
$ErrorActionPreference = "Stop"
Add-Type -Path "C:\projects\simagic-evo-sport-modification\tools\fwlib.cs"

$SfuSport = "$env:LOCALAPPDATA\SIMAGIC\firmware\base\alpha_evo1\Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu"
$SfuPro   = "$env:LOCALAPPDATA\SIMAGIC\firmware\base\alpha_evo2\Alpha_Evo_Pro_APP-V2.2.3.55-e942d5c2.sfu"
$Exe      = "C:\Program Files (x86)\simpro2\bin\simpro.exe"
$Dll      = "C:\Program Files (x86)\simpro2\bin\simpro_1.dll"

$sb = [IO.File]::ReadAllBytes($SfuSport)
$pb = [IO.File]::ReadAllBytes($SfuPro)
$cipher = [Fw2]::Slice($sb, 256, $sb.Length - 256)
$hdr = [Fw2]::Slice($sb, 0, 64)
$hashBlock = [Fw2]::Slice($sb, 0x40, 192)
$zero = New-Object byte[] 16
$W = [Console]::Out
$script:rows = New-Object System.Collections.ArrayList

function Test-Hyp([string]$label, [byte[]]$key, [byte[]]$iv) {
    $ecb = [Fw2]::Dec($key, $cipher, 0, 64, $false, $null)
    $cbc = [Fw2]::Dec($key, $cipher, 0, 64, $true, $iv)
    $tagE = [Fw2]::Magic($ecb); $tagC = [Fw2]::Magic($cbc)
    if (-not $tagE) { $tagE = "-" }
    if (-not $tagC) { $tagC = "-" }
    $W.WriteLine(("{0,-44} AES-{1} | ECB b3={2:x2} tag={3} {4} | CBC b3={5:x2} tag={6} {7}" -f `
        $label, ($key.Length*8), $ecb[3], $tagE, [Fw2]::Hex($ecb,32), $cbc[3], $tagC, [Fw2]::Hex($cbc,32)))
    [void]$script:rows.Add([pscustomobject]@{ test=$label; mode="ECB"; keylen=$key.Length*8; b3=("{0:x2}" -f $ecb[3]); tag=$tagE; head=[Fw2]::Hex($ecb,32); cbc_tag=$tagC; cbc_head=[Fw2]::Hex($cbc,32) })
}

$devA = [Text.Encoding]::ASCII.GetBytes("alpha_evo1")
$devB = [Text.Encoding]::ASCII.GetBytes("alpha_evo2")
$verS = [Text.Encoding]::ASCII.GetBytes("2.2.3")
$sim  = [Text.Encoding]::ASCII.GetBytes("simagic")

$W.WriteLine("=== TASK 1: remaining key hypotheses (payload at 0x100, 190144 bytes, ECB vs CBC/zero IV) ===")
$ka = [Fw2]::Sha256([Fw2]::Concat($devA,$verS)); Test-Hyp "A SHA256(alpha_evo1+2.2.3) k128" ([Fw2]::Slice($ka,0,16)) $zero; Test-Hyp "A SHA256(alpha_evo1+2.2.3) k256" $ka $zero

$uuids = @("3463535048588791808","3463535371365650432","3243493669008838656","3243498132926894080")
foreach ($u in $uuids) {
  $le = [BitConverter]::GetBytes([uint64]$u); $k16 = [Fw2]::Concat($le,$le)
  $h = [Fw2]::Hmac($k16, $cipher)
  Test-Hyp ("C HMAC(uuid $u,payload) k128") ([Fw2]::Slice($h,0,16)) $zero
  Test-Hyp ("C HMAC(uuid $u,payload) k256") $h $zero
  Test-Hyp ("D board-uuid $u k128") ([Fw2]::Slice($k16,0,16)) $zero
}
$ke = [Fw2]::Sha256([Fw2]::Concat($devA,[Text.Encoding]::ASCII.GetBytes("00000000"))); Test-Hyp "E SHA256(alpha_evo1+00000000) k128" ([Fw2]::Slice($ke,0,16)) $zero; Test-Hyp "E SHA256(alpha_evo1+00000000) k256" $ke $zero
Test-Hyp "F MD5(SFU header 0x00..0x3F)" ([Fw2]::Md5($hdr)) $zero
$kg = [Fw2]::Sha256([Fw2]::Slice($cipher,0,32)); Test-Hyp "G SHA256(payload[0:32]) k128" ([Fw2]::Slice($kg,0,16)) $zero; Test-Hyp "G SHA256(payload[0:32]) k256" $kg $zero
$kh = [Fw2]::Hmac($devA, [Fw2]::Hmac($devA,$sim)); Test-Hyp "H nested HMAC(alpha_evo1,simagic) k128" ([Fw2]::Slice($kh,0,16)) $zero; Test-Hyp "H nested HMAC(alpha_evo1,simagic) k256" $kh $zero
$ki = [Fw2]::Sha256([Fw2]::Slice($sb,0x10,32)); Test-Hyp "I SHA256(header 0x10..0x2F raw) k128" ([Fw2]::Slice($ki,0,16)) $zero; Test-Hyp "I SHA256(header 0x10..0x2F raw) k256" $ki $zero

$bui = [Text.Encoding]::ASCII.GetBytes("1@3*5!~8^0#1&34%")
Test-Hyp "X BUI key, IV=hashBlock[0:16]" $bui ([Fw2]::Slice($hashBlock,0,16))
Test-Hyp "X BUI key, IV=header 0x30..0x3F" $bui ([Fw2]::Slice($sb,0x30,16))
Test-Hyp "X BUI key, IV=hashBlock[176:16]" $bui ([Fw2]::Slice($hashBlock,176,16))
Test-Hyp "X BUI key x2 as AES-256" ([Fw2]::Concat($bui,$bui)) $zero
Test-Hyp "X BUI key, IV=cipher[0:16]" $bui ([Fw2]::Slice($cipher,0,16))

$W.WriteLine("")
$W.WriteLine("=== digest probe on the 192-byte block 0x40..0xFF (identical in Sport and Pro: " + ([Fw2]::Hex([Fw2]::Slice($pb,0x40,192),192) -eq [Fw2]::Hex($hashBlock,192)) + ") ===")
$digests = [ordered]@{
  "SHA256(payload)" = [Fw2]::Sha256($cipher)
  "SHA1(payload)"   = [Fw2]::Sha1($cipher)
  "SHA384(payload)" = [Fw2]::Sha384($cipher)
  "SHA512(payload)" = [Fw2]::Sha512($cipher)
  "MD5(payload)"    = [Fw2]::Md5($cipher)
  "SHA256(hdr+payload)" = [Fw2]::Sha256([Fw2]::Concat($hdr,$cipher))
  "SHA256(hdr0..255+payload)" = [Fw2]::Sha256([Fw2]::Concat([Fw2]::Slice($sb,0,256),$cipher))
}
foreach ($k in $digests.Keys) {
  $d = $digests[$k]
  $inBlock = [Fw2]::IndexOf($hashBlock, $d, 0, 192)
  $inHead  = [Fw2]::IndexOf([Fw2]::Slice($sb,0,256), $d, 0, 256)
  $W.WriteLine(("{0,-28} {1}  inHashBlock={2} inHeader256={3}" -f $k, [Fw2]::Hex($d,32), $inBlock, $inHead))
}
$W.WriteLine(("CRC32(payload)=0x{0:x8} inHashBlock={1}" -f [Fw2]::Crc32($cipher), [Fw2]::IndexOf($hashBlock,[BitConverter]::GetBytes([Fw2]::Crc32($cipher)),0,192)))

$W.WriteLine("")
$W.WriteLine("=== TASK 2/3: literal key candidates in the binaries ===")
foreach ($target in @(@("simpro.exe",$Exe),@("simpro_1.dll",$Dll))) {
  $name = $target[0]; $bytes = [IO.File]::ReadAllBytes($target[1])
  $a16 = [Fw2]::Ascii16($bytes); $h32 = [Fw2]::Hex32($bytes); $b64 = [Fw2]::Base64Keys($bytes)
  $W.WriteLine(("${name}: ascii16={0} hex32={1} base64->16={2}" -f $a16.Count,$h32.Count,$b64.Count))
  $found = 0
  foreach ($set in @(@("ascii",$a16),@("hex",$h32),@("b64",$b64))) {
    foreach ($k in $set[1]) {
      $tag = [Fw2]::Probe($k, $cipher)
      if ($tag) { $W.WriteLine(("  HIT {0} {1} {2}" -f $set[0], [Fw2]::Hex($k,16), $tag)); $found++ }
    }
  }
  $W.WriteLine("  hits=$found")
}

$W.WriteLine("")
$W.WriteLine("=== raw 16-byte window sweep (AES-128) ===")
foreach ($target in @(@("simpro.exe",$Exe),@("simpro_1.dll",$Dll))) {
  $name = $target[0]; $bytes = [IO.File]::ReadAllBytes($target[1])
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $hits = [Fw2]::RawSweep($bytes, $cipher, 0, $bytes.Length)
  $sw.Stop()
  $W.WriteLine(("${name}: {0} windows, {1:N1}s, hits={2}" -f ($bytes.Length-16), $sw.Elapsed.TotalSeconds, $hits.Count))
  $hits | Select-Object -First 20 | ForEach-Object { "  RAW " + $_ }
}

$script:rows | ConvertTo-Json -Depth 4 | Set-Content "C:\projects\simagic-evo-sport-modification\tools\fw_hypotheses.json" -Encoding UTF8


