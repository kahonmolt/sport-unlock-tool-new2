# Post-reboot Simagic USB capture. Runs elevated from the AtLogOn task.
# 1) wait for the wheel   2) start SimPro if needed   3) USBPcap all root hubs 60 s
# 4) parse the pcaps with tools\pcap_usb_extract.py
param(
    [int]$DeviceWait = 180,
    [int]$CaptureSeconds = 60,
    [string]$Root = "C:\projects\simagic-evo-sport-modification"
)

$ErrorActionPreference = 'Continue'
$out = Join-Path $Root 'tools\usbcap'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$log = Join-Path $out 'postreboot.log'
function Say($msg) {
    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Add-Content -Path $log -Value $line
    Write-Host $line
}
Set-Content -Path $log -Value "post-reboot capture start"

# One-shot self-disable: drop tools\usbcap\DISABLE_TASK and start the task once.
if (Test-Path (Join-Path $Root 'tools\usbcap\DISABLE_TASK')) {
    schtasks.exe /Change /TN "Simagic USBPcap capture (player1)" /DISABLE | Out-Null
    Say "capture task disabled on request (DISABLE_TASK marker present)"
    exit 0
}

Say "elevated=$((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"

Say "waiting up to ${DeviceWait}s for SIMAGIC Alpha EVO Sport"
$dev = $null
$deadline = (Get-Date).AddSeconds($DeviceWait)
while ((Get-Date) -lt $deadline) {
    $dev = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -like '*VID_3670&PID_0500*' }
    if ($dev) { break }
    Start-Sleep -Seconds 3
}
if (-not $dev) { Say "FAIL: wheel not present"; exit 2 }
Say "wheel present: $($dev[0].FriendlyName)"

# The filter creates \\.\USBPcapN only after boot with the driver attached.
# QueryDosDevice does not list these names; try to open each one instead.
$caps = @()
foreach ($i in 1..8) {
    try {
        $fs = [IO.File]::Open("\\.\USBPcap$i", 'Open', 'ReadWrite')
        $fs.Close()
        $caps += "USBPcap$i"
    } catch {
        if ($_.Exception.Message -notmatch 'Could not find') { $caps += "USBPcap$i" }
    }
}
if (-not $caps) {
    Say "FAIL: no USBPcap control devices. Driver did not attach at boot."
    Say "check: sc query USBPcap ; UpperFilters ; then reboot again"
    exit 3
}
Say "control devices: $($caps -join ', ')"

# SimPro must be running so the wheel is polled during the capture.
$simpro = Get-Process -Name simpro -ErrorAction SilentlyContinue
if (-not $simpro) {
    Say "starting SimPro"
    Start-Process -FilePath 'C:\Program Files (x86)\simpro2\bin\simpro.exe' -WorkingDirectory 'C:\Program Files (x86)\simpro2\bin'
    Start-Sleep -Seconds 40
} else {
    Say "SimPro already running ($($simpro.Count) processes)"
}

Say "capturing $CaptureSeconds s"
& (Join-Path $Root 'tools\usbpcap_capture.ps1') -Seconds $CaptureSeconds -OutDir $out | Out-Null
$files = @(Get-ChildItem $out -Filter 'hub*.pcap')
foreach ($f in $files) { Say ("pcap {0} {1} bytes" -f $f.Name, $f.Length) }
$total = ($files | Measure-Object -Property Length -Sum).Sum
if (-not $files -or $total -eq 0) {
    Say "FAIL: all pcaps are empty - USBPcapCMD opened the device but captured nothing"
    exit 4
}

$py = 'C:\Users\Player1\AppData\Local\Programs\Python\Python310\python.exe'
if (-not (Test-Path $py)) { $py = 'python' }
$report = Join-Path $out 'pcap_extract.txt'
Set-Content -Path $report -Value "Simagic HID transfers from post-reboot capture"
foreach ($f in $files) {
    Add-Content $report "`n===== $($f.Name) ====="
    & $py (Join-Path $Root 'tools\pcap_usb_extract.py') $f.FullName 2>&1 | Add-Content $report
}
Say "wrote $report"
Set-Content -Path (Join-Path $out 'DONE.txt') -Value (Get-Date -Format 'o')
Say "done"
