// Frida hook: log HID traffic of simpro.exe (Simagic SimPro Manager 2)
// Target: WriteFile/ReadFile/HidD_SetOutputReport/HidD_GetFeature/HidD_SetFeature
// Only handles opened on the Simagic HID device (VID_3670) are logged.
'use strict';

const hidHandles = new Set();
const MAXLEN = 512;

function hex(bytes) {
  const u = new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < u.length; i++) s += (u[i] < 16 ? '0' : '') + u[i].toString(16);
  return s;
}
function emit(o) { send(o); }

// HID reports on this device are 64 bytes (out) / 64 bytes (in) / 241 (feature).
// Handle filter alone is unreliable because simpro opens the device before we attach,
// so report-sized traffic is logged regardless of handle and tagged for later filtering.
function looksLikeReport(len) {
  return len === 64 || len === 65 || len === 241 || len === 242 || len === 32 || len === 33;
}

function getExport(mod, name) {
  try {
    const m = Process.getModuleByName(mod);
    return m.getExportByName(name);
  } catch (e) {
    try { return Module.getGlobalExportByName(name); } catch (e2) { return null; }
  }
}

// --- CreateFileW: map HID handle -> device path -------------------------
const pCreateFileW = getExport('kernel32.dll', 'CreateFileW');
if (pCreateFileW) {
  Interceptor.attach(pCreateFileW, {
    onEnter(args) {
      try {
        this.path = args[0].isNull() ? null : args[0].readUtf16String();
        this.access = args[1].toInt32();
        this.share = args[2].toInt32();
        this.creation = args[4].toInt32();
      } catch (e) { this.path = null; }
    },
    onLeave(ret) {
      try {
        if (this.path && /vid_3670/i.test(this.path) && ret.toInt32() !== -1) {
          const h = ret.toString();
          hidHandles.add(h);
          emit({ api: 'CreateFileW', handle: h, path: this.path, access: this.access, share: this.share, creation: this.creation });
        }
      } catch (e) {}
    }
  });
}

// --- WriteFile: output reports -----------------------------------------
const pWriteFile = getExport('kernel32.dll', 'WriteFile');
if (pWriteFile) {
  Interceptor.attach(pWriteFile, {
    onEnter(args) {
      this.h = args[0].toString();
      this.buf = args[1];
      this.len = args[2].toInt32();
      this.ov = args[4];
      this.isHid = hidHandles.has(this.h) || (this.len > 0 && looksLikeReport(this.len));
      if (!this.isHid) return;
      let n = Math.min(this.len, MAXLEN);
      let data = null;
      try { data = hex(this.buf.readByteArray(n)); } catch (e) {}
      emit({ api: 'WriteFile', phase: 'enter', handle: this.h, len: this.len, known: hidHandles.has(this.h), data: data });
    },
    onLeave(ret) {
      if (!this.isHid) return;
      emit({ api: 'WriteFile', phase: 'leave', handle: this.h, ok: ret.toInt32() !== 0 });
    }
  });
}

// --- ReadFile: input reports -------------------------------------------
const pReadFile = getExport('kernel32.dll', 'ReadFile');
if (pReadFile) {
  Interceptor.attach(pReadFile, {
    onEnter(args) {
      this.h = args[0].toString();
      this.buf = args[1];
      this.len = args[2].toInt32();
      this.pread = args[3];
      this.isHid = hidHandles.has(this.h) || (this.len > 0 && looksLikeReport(this.len));
      if (!this.isHid) return;
      emit({ api: 'ReadFile', phase: 'enter', handle: this.h, len: this.len, known: hidHandles.has(this.h) });
    },
    onLeave(ret) {
      if (!this.isHid) return;
      let got = 0;
      try { if (this.pread && !this.pread.isNull()) got = this.pread.readU32(); } catch (e) {}
      let data = null;
      if (ret.toInt32() !== 0 && got > 0) {
        try { data = hex(this.buf.readByteArray(Math.min(got, MAXLEN))); } catch (e) {}
      }
      emit({ api: 'ReadFile', phase: 'leave', handle: this.h, ok: ret.toInt32() !== 0, got: got, data: data });
    }
  });
}

// --- HidD_SetOutputReport ----------------------------------------------
const pHidSetOut = getExport('hid.dll', 'HidD_SetOutputReport');
if (pHidSetOut) {
  Interceptor.attach(pHidSetOut, {
    onEnter(args) {
      this.h = args[0].toString();
      this.buf = args[1];
      this.len = args[2].toInt32();
      let data = null;
      try { data = hex(this.buf.readByteArray(Math.min(this.len, MAXLEN))); } catch (e) {}
      emit({ api: 'HidD_SetOutputReport', phase: 'enter', handle: this.h, len: this.len, data: data });
    },
    onLeave(ret) {
      emit({ api: 'HidD_SetOutputReport', phase: 'leave', handle: this.h, ok: ret.toInt32() !== 0 });
    }
  });
}

// --- HidD_GetFeature / HidD_SetFeature ---------------------------------
function hookFeature(name, tag) {
  const p = getExport('hid.dll', name);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) {
      this.h = args[0].toString();
      this.buf = args[1];
      this.len = args[2].toInt32();
      let data = null;
      try { data = hex(this.buf.readByteArray(Math.min(this.len, MAXLEN))); } catch (e) {}
      emit({ api: tag, phase: 'enter', handle: this.h, len: this.len, data: data });
    },
    onLeave(ret) {
      let data = null;
      try { data = hex(this.buf.readByteArray(Math.min(this.len, MAXLEN))); } catch (e) {}
      emit({ api: tag, phase: 'leave', handle: this.h, ok: ret.toInt32() !== 0, data: data });
    }
  });
}
hookFeature('HidD_GetFeature', 'HidD_GetFeature');
hookFeature('HidD_SetFeature', 'HidD_SetFeature');

// --- HidD_GetInputReport ----------------------------------------------
const pHidGetIn = getExport('hid.dll', 'HidD_GetInputReport');
if (pHidGetIn) {
  Interceptor.attach(pHidGetIn, {
    onEnter(args) {
      this.h = args[0].toString();
      this.buf = args[1];
      this.len = args[2].toInt32();
      emit({ api: 'HidD_GetInputReport', phase: 'enter', handle: this.h, len: this.len });
    },
    onLeave(ret) {
      let data = null;
      try { data = hex(this.buf.readByteArray(Math.min(this.len, MAXLEN))); } catch (e) {}
      emit({ api: 'HidD_GetInputReport', phase: 'leave', handle: this.h, ok: ret.toInt32() !== 0, data: data });
    }
  });
}

// --- DeviceIoControl (HID IOCTLs) -------------------------------------
const pDevIoCtl = getExport('kernel32.dll', 'DeviceIoControl');
if (pDevIoCtl) {
  Interceptor.attach(pDevIoCtl, {
    onEnter(args) {
      this.h = args[0].toString();
      this.code = args[1].toInt32() >>> 0;
      this.inbuf = args[2];
      this.inlen = args[3].toInt32();
      let data = null;
      if (this.inlen > 0 && this.inlen < 4096) {
        try { data = hex(this.inbuf.readByteArray(Math.min(this.inlen, MAXLEN))); } catch (e) {}
      }
      emit({ api: 'DeviceIoControl', phase: 'enter', handle: this.h, code: '0x' + this.code.toString(16), len: this.inlen, data: data });
    },
    onLeave(ret) {
      emit({ api: 'DeviceIoControl', phase: 'leave', handle: this.h, ok: ret.toInt32() !== 0 });
    }
  });
}

emit({ api: 'ready', pid: Process.id, arch: Process.arch, modules: Process.enumerateModules().length });
