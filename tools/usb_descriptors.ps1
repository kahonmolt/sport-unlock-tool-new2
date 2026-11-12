#requires -Version 5
# Read-only USB/HID descriptor dump for the Simagic base (VID 3670, PID 0500).
# Uses Windows PnP properties + hid.dll. No traffic is generated or captured.
$ErrorActionPreference = 'Continue'

$src = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class Hid {
    [StructLayout(LayoutKind.Sequential)]
    public struct HIDD_ATTRIBUTES { public int Size; public ushort VendorID; public ushort ProductID; public ushort VersionNumber; }

    [DllImport("hid.dll")] public static extern void HidD_GetHidGuid(out Guid guid);
    [DllImport("hid.dll")] public static extern bool HidD_GetAttributes(IntPtr dev, ref HIDD_ATTRIBUTES attr);
    [DllImport("hid.dll")] public static extern bool HidD_GetPreparsedData(IntPtr dev, out IntPtr data);
    [DllImport("hid.dll")] public static extern bool HidD_FreePreparsedData(IntPtr data);
    [DllImport("hid.dll", CharSet = CharSet.Unicode)] public static extern bool HidD_GetManufacturerString(IntPtr dev, StringBuilder buf, int len);
    [DllImport("hid.dll", CharSet = CharSet.Unicode)] public static extern bool HidD_GetProductString(IntPtr dev, StringBuilder buf, int len);
    [DllImport("hid.dll", CharSet = CharSet.Unicode)] public static extern bool HidD_GetSerialNumberString(IntPtr dev, StringBuilder buf, int len);
    [DllImport("hid.dll")] public static extern int HidP_GetCaps(IntPtr preparsed, byte[] caps);
    [DllImport("hid.dll")] public static extern bool HidD_GetFeature(IntPtr dev, byte[] buf, int len);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inBuf, int inLen, byte[] outBuf, int outLen, out int ret, IntPtr ov);

    public static string Words(byte[] b, int off, int n) {
        var sb = new StringBuilder();
        for (int i = 0; i < n && off + i < b.Length; i++) sb.Append(b[off + i].ToString("x2"));
        return sb.ToString();
    }

    public static string Dump(string path) {
        var sb = new StringBuilder();
        IntPtr h = CreateFileW(path, 0, 3 /*FILE_SHARE_READ|WRITE*/, IntPtr.Zero, 3 /*OPEN_EXISTING*/, 0, IntPtr.Zero);
        if (h == new IntPtr(-1)) { sb.AppendLine("  CreateFile failed: " + Marshal.GetLastWin32Error()); return sb.ToString(); }
        try {
            var a = new HIDD_ATTRIBUTES(); a.Size = Marshal.SizeOf(a);
            if (HidD_GetAttributes(h, ref a)) sb.AppendLine(String.Format("  HID attributes : VID=0x{0:X4} PID=0x{1:X4} version=0x{2:X4}", a.VendorID, a.ProductID, a.VersionNumber));
            var ms = new StringBuilder(256); var ps = new StringBuilder(256); var sn = new StringBuilder(256);
            if (HidD_GetManufacturerString(h, ms, 512)) sb.AppendLine("  manufacturer   : " + ms.ToString());
            if (HidD_GetProductString(h, ps, 512)) sb.AppendLine("  product        : " + ps.ToString());
            if (HidD_GetSerialNumberString(h, sn, 512)) sb.AppendLine("  serial         : " + sn.ToString());

            IntPtr pd;
            if (HidD_GetPreparsedData(h, out pd)) {
                var caps = new byte[256];
                if (HidP_GetCaps(pd, caps) >= 0) {
                    int usage = BitConverter.ToUInt16(caps, 0), page = BitConverter.ToUInt16(caps, 2);
                    sb.AppendLine(String.Format("  usagePage/usage: 0x{0:X4} / 0x{1:X4}", page, usage));
                    sb.AppendLine(String.Format("  report lengths : in={0} out={1} feature={2} bytes",
                        BitConverter.ToUInt16(caps, 4), BitConverter.ToUInt16(caps, 6), BitConverter.ToUInt16(caps, 8)));
                    sb.AppendLine(String.Format("  caps counts    : link={0} inBtn={1} inVal={2} outBtn={3} outVal={4} featBtn={5} featVal={6}",
                        BitConverter.ToUInt16(caps, 44), BitConverter.ToUInt16(caps, 46), BitConverter.ToUInt16(caps, 48),
                        BitConverter.ToUInt16(caps, 52), BitConverter.ToUInt16(caps, 54),
                        BitConverter.ToUInt16(caps, 58), BitConverter.ToUInt16(caps, 60)));
                }
                HidD_FreePreparsedData(pd);
            }

            // IOCTL_HID_GET_REPORT_DESCRIPTOR = CTL_CODE(FILE_DEVICE_HID=0x0B, 1, METHOD_NEITHER=3, ANY=0)
            uint ioctl = (0x0Bu << 16) | (0x01u << 2) | 3u;
            var buf = new byte[4096];
            int ret;
            if (DeviceIoControl(h, ioctl, null, 0, buf, buf.Length, out ret, IntPtr.Zero) && ret > 0) {
                sb.AppendLine(String.Format("  report desc    : {0} bytes", ret));
                int n = Math.Min(ret, 256);
                for (int i = 0; i < n; i += 16) {
                    int m = Math.Min(16, n - i);
                    sb.AppendLine("    " + (i).ToString("x4") + "  " + Words(buf, i, m));
                }
            } else {
                sb.AppendLine("  report desc    : IOCTL failed (" + Marshal.GetLastWin32Error() + ")");
            }
        } finally { CloseHandle(h); }
        return sb.ToString();
    }
}
"@
Add-Type -TypeDefinition $src -Language CSharp

$instances = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -match 'VID_3670&PID_0500' } | Select-Object -ExpandProperty InstanceId

"== PnP nodes for VID_3670&PID_0500 =="
foreach ($i in $instances) { "  $i" }
""
foreach ($i in $instances) {
    "== $i =="
    foreach ($key in 'DEVPKEY_Device_BusReportedDeviceDesc','DEVPKEY_Device_Manufacturer','DEVPKEY_Device_DriverDesc','DEVPKEY_Device_HardwareIds','DEVPKEY_Device_CompatibleIds','DEVPKEY_Device_BusNumber','DEVPKEY_Device_Address','DEVPKEY_Device_LocationInfo','DEVPKEY_Device_Service','DEVPKEY_Device_DriverVersion') {
        $v = (Get-PnpDeviceProperty -InstanceId $i -KeyName $key -ErrorAction SilentlyContinue).Data
        if ($v) { "  {0,-38} {1}" -f ($key -replace 'DEVPKEY_Device_',''), ($v -join ', ') }
    }
    $iface = (Get-PnpDeviceProperty -InstanceId $i -KeyName 'DEVPKEY_Device_Interface' -ErrorAction SilentlyContinue).Data
    if ($iface) { "  interface(s)   :"; foreach ($p in $iface) { "    $p" } }
    ""
}

"== HID descriptor dump per interface =="
$cls = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\{4d1e55b2-f16f-11cf-88cb-001111000030}'
$paths = @()
Get-ChildItem $cls -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match 'VID_3670' } | ForEach-Object {
    $paths += ('\\?\' + ($_.PSChildName -replace '^##\?#', ''))
}
foreach ($i in $instances) {
    $iface = (Get-PnpDeviceProperty -InstanceId $i -KeyName 'DEVPKEY_Device_Interface' -ErrorAction SilentlyContinue).Data
    foreach ($p in $iface) { if ($p) { $paths += $p } }
}
$paths = $paths | Sort-Object -Unique
foreach ($p in $paths) {
    "  --- $p"
    [Hid]::Dump($p)
}

