# Capture Simagic USB traffic with USBPcap (run after a reboot, elevated).
# Captures every root hub in parallel for 60 s; filter VID 0x3670 when parsing.
param(
    [int]$Seconds = 60,
    [string]$OutDir = "C:\projects\simagic-evo-sport-modification\tools\usbcap"
)

$exe = 'C:\Program Files\USBPcap\USBPcapCMD.exe'
if (-not (Test-Path $exe)) { throw "USBPcapCMD.exe not found" }

$svc = (sc.exe query USBPcap 2>&1 | Out-String)
if ($svc -notmatch 'RUNNING') { throw "USBPcap driver not RUNNING. Reboot first.`n$svc" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Get-ChildItem $OutDir -Filter 'hub*.pcap' -ErrorAction SilentlyContinue | Remove-Item -Force

$procs = @()
foreach ($i in 1..8) {
    $out = Join-Path $OutDir "hub$i.pcap"
    $err = Join-Path $OutDir "hub$i.err.txt"
    # A missing control device fails immediately; that is fine, we keep going.
    $p = Start-Process -FilePath $exe `
        -ArgumentList @('-d', "\\.\USBPcap$i", '-o', $out, '-s', '512', '-b', '4096', '-A', '--inject-descriptors') `
        -PassThru -WindowStyle Hidden -RedirectStandardError $err
    $procs += [pscustomobject]@{ Hub = $i; Pid = $p.Id; File = $out; Err = $err }
    Start-Sleep -Milliseconds 250
}

Write-Host "capturing $Seconds s on $($procs.Count) root hubs..."
Start-Sleep -Seconds $Seconds

foreach ($p in $procs) {
    $proc = Get-Process -Id $p.Pid -ErrorAction SilentlyContinue
    if ($proc) { Stop-Process -Id $p.Pid -Force }
}
Start-Sleep -Seconds 2

$procs | ForEach-Object {
    $size = if (Test-Path $_.File) { (Get-Item $_.File).Length } else { 0 }
    $errText = ''
    if (Test-Path $_.Err) {
        $raw = Get-Content $_.Err -Raw
        if ($null -ne $raw) { $errText = $raw.Trim() }
    }
    [pscustomobject]@{
        Hub     = "USBPcap$($_.Hub)"
        Bytes   = $size
        Pcap    = $_.File
        Stderr  = $errText
    }
} | Format-Table -AutoSize

Write-Host "`nNext: filter VID 0x3670 (13936) and extract HID feature/output reports."
Write-Host "The wheel hangs off USB\ROOT_HUB30\7&276CE0A&0&0 (AMD xHCI PCI\VEN_1022&DEV_43FC)."
