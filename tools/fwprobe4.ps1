#requires -Version 5
$ErrorActionPreference = "Stop"
Add-Type -Path "C:\projects\simagic-evo-sport-modification\tools\fwlib.cs"
$W = [Console]::Out
$SfuSport = "$env:LOCALAPPDATA\SIMAGIC\firmware\base\alpha_evo1\Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu"
$Exe = "C:\Program Files (x86)\simpro2\bin\simpro.exe"
$sb = [IO.File]::ReadAllBytes($SfuSport)
$cipher = [Fw2]::Slice($sb, 256, $sb.Length - 256)
$bui = [Text.Encoding]::ASCII.GetBytes("1@3*5!~8^0#1&34%")
$zero = New-Object byte[] 16
$hdr30 = [Fw2]::Slice($sb, 0x30, 16)

$W.WriteLine("=== CTR-mode probe (AES-CTR, counter in last 4 bytes) ===")
function ProbeCtr([string]$label, [byte[]]$key, [byte[]]$ivPrefix, [uint32]$counter) {
    $ctr = New-Object byte[] 16
    if ($ivPrefix) { [Array]::Copy($ivPrefix, 0, $ctr, 0, [Math]::Min(12, $ivPrefix.Length)) }
    $cb = [BitConverter]::GetBytes($counter); if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($cb) }
    [Array]::Copy($cb, 0, $ctr, 12, 4)
    $ks = [Fw4]::CtrBlock($key, $ctr)
    $pt = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) { $pt[$i] = $cipher[$i] -bxor $ks[$i] }
    $tag = [Fw2]::Magic($pt); if (-not $tag) { $tag = "-" }
    $W.WriteLine(("{0,-38} tag={1} {2}" -f $label, $tag, [Fw2]::Hex($pt,16)))
}
ProbeCtr "BUI key, iv=0, ctr=0" $bui $null 0
ProbeCtr "BUI key, iv=0, ctr=1" $bui $null 1
ProbeCtr "BUI key, iv=hdr30, ctr=0" $bui $hdr30 0
ProbeCtr "BUI key, iv=hdr30, ctr=1" $bui $hdr30 1

$W.WriteLine("")
$W.WriteLine("=== XOR-obfuscated 16-byte key sweep over simpro.exe (AES-128) ===")
$exeB = [IO.File]::ReadAllBytes($Exe)
foreach ($spec in @(@(0xFF,$false),@(0xAA,$false),@(0x55,$false),@(0x5A,$false),@(0x00,$true))) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $hits = [Fw4]::SweepMask($exeB, $cipher, 0, $exeB.Length, [byte]$spec[0], [bool]$spec[1])
    $sw.Stop()
    $W.WriteLine(("mask=0x{0:x2} reverse={1}: {2:N1}s hits={3}" -f $spec[0], $spec[1], $sw.Elapsed.TotalSeconds, $hits.Count))
    $hits | Select-Object -First 5 | ForEach-Object { "  " + $_ }
}

$W.WriteLine("")
$W.WriteLine("=== is the 192-byte block (0x40..0xFF) a chunked digest of the payload? ===")
$hb = [Fw2]::Slice($sb, 0x40, 192)
$algs = @(
  @("SHA256", { param($b) [Fw2]::Sha256($b) }),
  @("SHA1",   { param($b) [Fw2]::Sha1($b) }),
  @("MD5",    { param($b) [Fw2]::Md5($b) }),
  @("SHA384", { param($b) [Fw2]::Sha384($b) }),
  @("SHA512", { param($b) [Fw2]::Sha512($b) })
)
$whole = [Fw2]::Concat($sb)
foreach ($n in 1,2,3,4,6,8,12) {
    $chunk = [int][Math]::Floor($cipher.Length / $n)
    $okCount = 0; $checked = 0
    for ($c = 0; $c -lt $n; $c++) {
        $start = $c * $chunk
        $len = if ($c -eq $n-1) { $cipher.Length - $start } else { $chunk }
        $seg = [Fw2]::Slice($cipher, $start, $len)
        foreach ($a in $algs) {
            $d = & $a[1] $seg
            $pos = [Fw2]::IndexOf($hb, $d, 0, 192)
            $checked++
            if ($pos -ge 0) { $okCount++; $W.WriteLine(("  MATCH chunks={0} alg={1} chunk={2} at block offset {3}" -f $n, $a[0], $c, $pos)) }
        }
    }
    $W.WriteLine(("chunks={0}: matches={1}/{2}" -f $n, $okCount, $checked))
}
$W.WriteLine("whole-file digests vs block:")
foreach ($a in $algs) { $d = & $a[1] $whole; $W.WriteLine(("  {0}: pos={1}" -f $a[0], [Fw2]::IndexOf($hb,$d,0,192))) }
