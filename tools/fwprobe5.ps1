#requires -Version 5
$ErrorActionPreference = "Stop"
Add-Type -Path "C:\projects\simagic-evo-sport-modification\tools\fwlib.cs"
$W = [Console]::Out
$SfuSport = "$env:LOCALAPPDATA\SIMAGIC\firmware\base\alpha_evo1\Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu"
$sb = [IO.File]::ReadAllBytes($SfuSport)
$cipher = [Fw2]::Slice($sb, 256, $sb.Length - 256)
$hb = [Fw2]::Slice($sb, 0x40, 192)
$hdr30 = [Fw2]::Slice($sb, 0x30, 16)
$bui = [Text.Encoding]::ASCII.GetBytes("1@3*5!~8^0#1&34%")
$zero = New-Object byte[] 16

$sources = [ordered]@{
  "BUI" = $bui
  "hdr30" = $hdr30
  "hb[0:16]" = [Fw2]::Slice($hb,0,16)
  "hb[96:112]" = [Fw2]::Slice($hb,96,16)
  "hb[176:192]" = [Fw2]::Slice($hb,176,16)
  "MD5(BUI)" = [Fw2]::Md5($bui)
  "SHA256(BUI)[0:16]" = [Fw2]::Slice([Fw2]::Sha256($bui),0,16)
  "ZERO" = $zero
}
$ivs = [ordered]@{
  "iv0" = $zero
  "ivHdr30" = $hdr30
  "ivHb0" = [Fw2]::Slice($hb,0,16)
  "ivHb176" = [Fw2]::Slice($hb,176,16)
  "ivCipher0" = [Fw2]::Slice($cipher,0,16)
}

$W.WriteLine("=== cartesian key x IV grid (payload and payload+16) ===")
$hits = 0
foreach ($kn in $sources.Keys) {
  foreach ($ivn in $ivs.Keys) {
    foreach ($skip in 0,16) {
      $data = if ($skip -eq 0) { $cipher } else { [Fw2]::Slice($cipher,$skip,$cipher.Length-$skip) }
      $d = [Fw2]::Dec($sources[$kn], $data, 0, 16, $true, $ivs[$ivn])
      $tag = [Fw2]::Magic($d)
      if ($tag) { $W.WriteLine("  HIT key=$kn $ivn skip=$skip tag=$tag " + [Fw2]::Hex($d,16)); $hits++ }
    }
  }
}
$W.WriteLine("grid hits=$hits")

$W.WriteLine("")
$W.WriteLine("=== wrapped-key idea: decrypt the 192-byte block, inspect and use its chunks as keys ===")
foreach ($kn in @("BUI","hdr30","ZERO")) {
  $pt = [Fw2]::Dec($sources[$kn], $hb, 0, 192, $true, $zero)
  $printable = 0
  foreach ($x in $pt) { if ($x -ge 0x20 -and $x -lt 0x7F) { $printable++ } }
  $W.WriteLine(("key={0}: printable={1}/192 head={2}" -f $kn, $printable, [Fw2]::Hex($pt,32)))
  for ($i = 0; $i -lt 192; $i += 16) {
    $k16 = [Fw2]::Slice($pt,$i,16)
    $tag = [Fw2]::Probe($k16, $cipher)
    if ($tag) { $W.WriteLine("  WRAPPED-HIT key=$kn chunk=$i " + [Fw2]::Hex($k16,16) + " " + $tag) }
  }
}

$W.WriteLine("")
$W.WriteLine("=== HMAC/digest of payload vs the 192-byte block ===")
$cands = @{
  "HMAC-SHA256(BUI,payload)" = [Fw2]::Hmac($bui, $cipher)
  "HMAC-SHA256(hdr30,payload)" = [Fw2]::Hmac($hdr30, $cipher)
  "HMAC-SHA256(alpha_evo1,payload)" = [Fw2]::Hmac([Text.Encoding]::ASCII.GetBytes("alpha_evo1"), $cipher)
  "HMAC-SHA256(simagic,payload)" = [Fw2]::Hmac([Text.Encoding]::ASCII.GetBytes("simagic"), $cipher)
  "SHA256(payload[16:])" = [Fw2]::Sha256([Fw2]::Slice($cipher,16,$cipher.Length-16))
  "SHA256(payload+header64)" = [Fw2]::Sha256([Fw2]::Concat($cipher,[Fw2]::Slice($sb,0,64)))
}
foreach ($k in $cands.Keys) {
  $d = $cands[$k]
  $W.WriteLine(("{0,-34} pos={1} head={2}" -f $k, [Fw2]::IndexOf($hb,$d,0,192), [Fw2]::Hex($d,16)))
}

$W.WriteLine("")
$W.WriteLine("=== header field map ===")
$W.WriteLine(("0x0E u16 = 0x{0:x4}" -f [BitConverter]::ToUInt16($sb,0x0E)))
$W.WriteLine(("0x30 u32 = 0x{0:x8} ({0})" -f [BitConverter]::ToUInt32($sb,0x30)))
$W.WriteLine(("0x34 u32 = 0x{0:x8} ({0})" -f [BitConverter]::ToUInt32($sb,0x34)))
$W.WriteLine(("0x38 u32 = 0x{0:x8} ({0})" -f [BitConverter]::ToUInt32($sb,0x38)))
$W.WriteLine(("0x3C u32 = 0x{0:x8} ({0})" -f [BitConverter]::ToUInt32($sb,0x3C)))
$W.WriteLine(("file size = {0}; 0x40 + field0x30 = {1}" -f $sb.Length, (0x40 + [BitConverter]::ToUInt32($sb,0x30))))
