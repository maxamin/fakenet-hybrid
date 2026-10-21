// FakeNet hybrid hook script for Frida: links the sample's network calls to its code.
// Run from a [[hook]] command, e.g.
//   command = ["frida", "-p", "{pid}", "-l", "<this file>", "-q", "-t", "inf"]
// Each connect/send/recv (Linux libc, Windows ws2_32) prints one JSON line with the calling
// thread's backtrace as module+offset (the address minus the module's base), which is what
// Ghidra and IDA need to jump to the code: in Ghidra, Navigation > Go To "<module>+<offset>",
// with the program's image base set as loaded. The hook's command.stdout holds the lines.
"use strict";

const MAX_FRAMES = 16;
const MAX_PREVIEW = 64;

function frame(address) {
  const module = Process.findModuleByAddress(address);
  if (!module) return { address: address.toString() };
  const symbol = DebugSymbol.fromAddress(address);
  return {
    module: module.name,
    offset: "0x" + address.sub(module.base).toString(16),
    symbol: symbol && symbol.name && !symbol.name.startsWith("0x") ? symbol.name : null,
  };
}

function preview(pointer, length) {
  if (pointer.isNull() || length <= 0) return null;
  try {
    const bytes = new Uint8Array(pointer.readByteArray(Math.min(length, MAX_PREVIEW)));
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  } catch (e) {
    return null;
  }
}

function report(call, context, extra) {
  // Accurate unwinding needs unwind info; stripped samples often lack it, so fall back to
  // scanning the stack (may include stale frames: marked)
  let frames = Thread.backtrace(context, Backtracer.ACCURATE);
  let fuzzy = false;
  if (frames.length <= 1) {
    frames = Thread.backtrace(context, Backtracer.FUZZY);
    fuzzy = true;
  }
  frames = frames.slice(0, MAX_FRAMES).map(frame);
  console.log(JSON.stringify(Object.assign({ call, thread: Process.getCurrentThreadId(), fuzzy, frames }, extra)));
}

// Socket address of a sockaddr* (IPv4/IPv6; others by family number)
function sockaddr(pointer) {
  if (pointer.isNull()) return null;
  try {
    const family = Process.platform === "windows" || Process.platform === "darwin" ? pointer.add(Process.platform === "darwin" ? 1 : 0).readU8() : pointer.readU16();
    const port = (pointer.add(2).readU8() << 8) | pointer.add(3).readU8();
    if (family === 2) return `${Array.from(new Uint8Array(pointer.add(4).readByteArray(4))).join(".")}:${port}`;
    if (family === 10 || family === 23 || family === 30) {
      const words = [];
      for (let i = 0; i < 16; i += 2) words.push(((pointer.add(8 + i).readU8() << 8) | pointer.add(9 + i).readU8()).toString(16));
      return `[${words.join(":")}]:${port}`;
    }
    return `family ${family}`;
  } catch (e) {
    return null;
  }
}

// Frida 17 removed the static Module.findExportByName; support both APIs
function findExport(module, name) {
  try {
    if (module === null) return typeof Module.findGlobalExportByName === "function" ? Module.findGlobalExportByName(name) : Module.findExportByName(null, name);
    const loaded = Process.findModuleByName(module);
    if (loaded && typeof loaded.findExportByName === "function") return loaded.findExportByName(name);
    return typeof Module.findExportByName === "function" ? Module.findExportByName(module, name) : null;
  } catch (e) {
    return null;
  }
}

function hook(module, name, onEnter) {
  const address = findExport(module, name);
  if (address) Interceptor.attach(address, { onEnter });
}

const sockets = Process.platform === "windows" ? "ws2_32.dll" : null;
hook(sockets, "connect", function (args) { report("connect", this.context, { to: sockaddr(args[1]) }); });
hook(sockets, "send", function (args) { report("send", this.context, { bytes: args[2].toInt32(), data: preview(args[1], args[2].toInt32()) }); });
hook(sockets, "sendto", function (args) { report("sendto", this.context, { bytes: args[2].toInt32(), to: sockaddr(args[4]), data: preview(args[1], args[2].toInt32()) }); });
hook(sockets, "recv", function (args) { report("recv", this.context, { max: args[2].toInt32() }); });
if (Process.platform === "windows") {
  hook("ws2_32.dll", "WSAConnect", function (args) { report("WSAConnect", this.context, { to: sockaddr(args[1]) }); });
  hook("ws2_32.dll", "WSASend", function (args) { report("WSASend", this.context, {}); });
  hook("ws2_32.dll", "WSARecv", function (args) { report("WSARecv", this.context, {}); });
  hook("winhttp.dll", "WinHttpSendRequest", function (args) { report("WinHttpSendRequest", this.context, {}); });
  hook("wininet.dll", "HttpSendRequestW", function (args) { report("HttpSendRequestW", this.context, {}); });
} else {
  hook(null, "write", function (args) {
    // Sockets only: fstat would be costly here, so report writes to descriptors above stderr
    if (args[0].toInt32() > 2) report("write", this.context, { fd: args[0].toInt32(), bytes: args[2].toInt32(), data: preview(args[1], args[2].toInt32()) });
  });
}
console.log(JSON.stringify({ call: "attached", pid: Process.id, platform: Process.platform, arch: Process.arch }));
