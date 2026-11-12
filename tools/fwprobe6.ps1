#requires -Version 5
$ErrorActionPreference = "Stop"
Add-Type -Path "C:\projects\simagic-evo-sport-modification\tools\fwlib.cs"
$W = [Console]::Out
$SfuSport = "$env:LOCALAPPDATA\SIMAGIC\firmware\base\alpha_evo1\Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu"
$sb = [IO.File]::ReadAllBytes($SfuSport)
$cipher = [Fw2]::Slice($sb, 256, $sb.Length - 256)
$zero = New-Object byte[] 16

$W.WriteLine("=== string / build-id derived keys ===")
$words = @("e942d5c2", "V2.2.3.55", "2.2.3.55", "2.2.3", "alpha_evo1", "alpha_evo2", "SIMPROSFU100", "SIMPROSFU", "simpro", "Simagic", "SIMAGIC", "firmware", "updateBaseFirmware", "Alpha_Evo_Sport", "Alpha_Evo_Pro")
$keys = New-Object System.Collections.ArrayList
foreach ($w0 in $words) {
  $b = [Text.Encoding]::ASCII.GetBytes($w0)
  $p16 = New-Object byte[] 16; [Array]::Copy($b, 0, $p16, 0, [Math]::Min(16,$b.Length))
  $sp16 = [Text.Encoding]::ASCII.GetBytes($w0.PadRight(16, ' ').Substring(0,16))
  [void]$keys.Add(@("ascii($w0)zero", $p16))
  [void]$keys.Add(@("ascii($w0)space", $sp16))
  [void]$keys.Add(@("MD5($w0)", [Fw2]::Md5($b)))
  [void]$keys.Add(@("SHA256($w0)k128", [Fw2]::Slice([Fw2]::Sha256($b),0,16)))
}
# header raw fields as keys
[void]$keys.Add(@("hdr0..15", [Fw2]::Slice($sb,0,16)))
[void]$keys.Add(@("hdr16..31", [Fw2]::Slice($sb,0x10,16)))
[void]$keys.Add(@("hdr32..47", [Fw2]::Slice($sb,0x20,16)))
$hits = 0
foreach ($k in $keys) {
  foreach ($mode in @("ecb","cbc")) {
    $d = [Fw2]::Dec($k[1], $cipher, 0, 16, ($mode -eq "cbc"), $zero)
    $tag = [Fw2]::Magic($d)
    if ($tag) { $W.WriteLine("  HIT $($k[0]) $mode $tag " + [Fw2]::Hex($d,16)); $hits++ }
  }
}
$W.WriteLine("string-key hits=$hits (tested $($keys.Count) keys x2 modes)")

$W.WriteLine("")
$W.WriteLine("=== 0x3C field (0x36700500) vs CRC32/sums ===")
$seg = @{
  "payload" = $cipher
  "header0..63" = [Fw2]::Slice($sb,0,64)
  "hashBlock" = [Fw2]::Slice($sb,0x40,192)
  "blob 0x40..end" = [Fw2]::Slice($sb,0x40,$sb.Length-0x40)
  "header0..63+payload" = [Fw2]::Concat([Fw2]::Slice($sb,0,64),$cipher)
}
foreach ($k in $seg.Keys) { $c = [Fw2]::Crc32($seg[$k]); $W.WriteLine(("{0,-20} crc32=0x{1:x8}" -f $k,$c)) }
$sum = 0uL; foreach ($x in $cipher) { $sum += $x }
$W.WriteLine(("payload byte sum = 0x{0:x8} ({0})" -f $sum))
$W.WriteLine(("0x3C field       = 0x36700500 (913310976)"))
