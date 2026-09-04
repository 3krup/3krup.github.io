---
title: "Undetected Is Not Invisible: Looking for VEH Debuggers with Rust"
date: "2026-09-04"
tags:
    - [Windows]
    - [Rust]
    - [Reverse Engineering]
    - [Blue Team]
    - [Anti-Debugging]
thumbnail: "/assets/img/veh-detection/thumbnail.webp"
bookmark: true
---

> **Summary:** GhostDebug leaves the usual Windows debugger checks untouched. I pulled apart how it works, then wrote a small Rust tool to watch for the state it does change: VEH registration, loaded modules, executable private memory, and patched `INT3` bytes.

---

## 1. How This Started

I found [GhostDebug](https://github.com/VollRagm/ghostdebug), an open-source Windows x64 debugger by [VollRagm](https://vollragm.github.io/), while reading about VEH-based debugging. It does not attach through the normal Windows debugging API, which made it a good target for a detection experiment.

Instead, GhostDebug injects a native DLL into the target. That DLL registers a Vectored Exception Handler (VEH), places `INT3` breakpoints, uses the CPU trap flag for single stepping, and talks to the command-line client through a named pipe.

It is a different model from the debuggers I had used before:

| Traditional debugger | VEH debugger |
|---|---|
| Usually controls the program from another process | Runs the important debugging logic inside the target |
| Uses APIs such as `DebugActiveProcess` and `WaitForDebugEvent` | Handles breakpoint and single-step exceptions through VEH |
| Creates conventional Windows debugging state | Does not need a debug port or debug object |
| Can often be found with familiar anti-debugging checks | Can leave those checks looking clean |

VollRagm documents the design in a four-part series covering [theory](https://vollragm.github.io/posts/developing-veh-debugger/), [detection](https://vollragm.github.io/posts/developing-veh-debugger-p2/), [implementation](https://vollragm.github.io/posts/developing-veh-debugger-p3/), and [evaluation](https://vollragm.github.io/posts/developing-veh-debugger-p4/). My question was narrower: if the classic checks stay clean, what changes inside the target?

When I attached GhostDebug, `IsDebuggerPresent()` still returned false. The PEB `BeingDebugged` field was not set, and there was no normal debug object.

The process was still being debugged, so I changed the question from:

> Is Windows telling me that a debugger is attached?

to:

> What changed inside the process when debugging started?

I am not generalizing one sample into a detector for every VEH debugger. I treated the project as a lab notebook: what I checked, what worked on my VM, and where the method breaks down.

### What I wanted to learn

- Why do the usual checks miss GhostDebug?
- Which parts of its design are still visible?
- Which observations are generic and which are just GhostDebug fingerprints?
- How much can I detect from one scan?
- How much stronger does detection become if I have a baseline from before attachment?

### Scope

I kept the test setup narrow:

- Windows 11 25H2, build 26200.8246;
- native 64-bit processes;
- a 64-bit detector;
- user-mode VEH debuggers;
- GhostDebug as the main sample.

Everything below assumes that setup. I would not ship this as an endpoint detector.

---

## 2. The Windows Pieces I Needed to Understand

### 2.1 Traditional Windows debugging

Debuggers such as WinDbg and x64dbg normally use the Windows debugging API. Windows keeps state for this relationship and sends events to the debugger. That gives programs several well-known checks:

- `IsDebuggerPresent`;
- `CheckRemoteDebuggerPresent`;
- the PEB `BeingDebugged` field;
- `NtQueryInformationProcess(ProcessDebugPort)`;
- `NtQueryInformationProcess(ProcessDebugObjectHandle)`;
- exception and timing behavior.

They are useful controls, but they describe the traditional debugger model.

### 2.2 Vectored Exception Handling

Vectored Exception Handling is a Windows mechanism that lets a process register callbacks for exceptions. The callbacks are not tied to the current stack frame. If a conventional debugger is attached, it receives the first-chance exception notification first. If the exception continues into the process, VEH runs before stack unwinding and frame-based Structured Exception Handling. VEH is not suspicious by itself: crash reporters, runtimes, instrumentation tools, anti-cheat products, and security software can all use it legitimately.

### 2.3 Turning VEH into a small debugger

A software breakpoint replaces an instruction byte with `INT3` (`0xCC`). When the processor reaches it, Windows raises `EXCEPTION_BREAKPOINT`.

A VEH callback can then:

1. recognize the breakpoint address;
2. restore the original byte;
3. inspect or change the thread context;
4. move `RIP` back to the original instruction;
5. enable the CPU trap flag;
6. continue execution;
7. receive the next `EXCEPTION_SINGLE_STEP`;
8. put the breakpoint back.

![Software-breakpoint lifecycle from the original instruction byte through INT3 handling and single stepping](/assets/img/veh-detection/breakpoint-lifecycle.webp)

*Figure 1: A VEH debugger restores the original instruction for one step, then reinserts the `INT3` breakpoint.*

Together, the breakpoint and single-step exceptions provide a debugging loop without a conventional Windows debug object.

---

## 3. Looking Through GhostDebug

GhostDebug has two main parts:

- a .NET command-line client;
- a native DLL that is loaded into the target process.

```text
GhostDebug CLI
    |
    | OpenProcess + VirtualAllocEx + WriteProcessMemory
    | CreateRemoteThread(LoadLibraryA)
    v
Target process
    |
    +-- injected native DLL
    +-- head-of-chain VEH callback at registration
    +-- INT3 breakpoint manager
    +-- trap-flag single stepping
    +-- named-pipe communication
```

### 3.1 Getting the DLL into the target

The controller opens the target, allocates memory for the DLL path, writes that path, and starts a remote thread at `LoadLibraryA`.

GhostDebug happens to use familiar `LoadLibrary` injection. I did not turn that sequence into a signature because another VEH debugger could use a different injector or load with the program from the start.

GhostDebug also creates its pipe, starts a listener thread, and registers the VEH callback during `DLL_PROCESS_ATTACH`. Doing that work inside `DllMain` carries loader-lock risk and is not a generic property of VEH debuggers; it mainly helps explain the timing of this sample's initialization.

### 3.2 The named pipe

GhostDebug uses a fixed named pipe so the client and injected DLL can exchange JSON commands. Those commands cover actions such as adding a breakpoint, continuing, stepping, and changing registers.

The fixed pipe name and DLL filename are easy to find and just as easy to change. The detector therefore ignores both.

### 3.3 Registering the handler

The core registers its callback with `AddVectoredExceptionHandler`:

```cpp
AddVectoredExceptionHandler(1, exception_handler);
```

The nonzero first argument places the callback at the head of the VEH chain when it is registered. It remains first only until another handler is registered with the same first-position request.

I also stopped the process on `RtlAddVectoredExceptionHandler` in WinDbg to confirm it at runtime:

![WinDbg showing GhostDebug registering its vectored exception handler](/assets/img/veh-detection/windbg.webp)

*Figure 2: WinDbg stopped while GhostDebug registered its handler. On Windows x64, `RCX` contains the first argument (`1`) and `RDX` points to the callback.*

### 3.4 Breakpoints and stepping

GhostDebug implements the lifecycle described in Section 2.3: it saves the original byte, changes the page protection, writes `0xCC`, and restores the old protection. While that breakpoint is armed, the executable code in memory differs from the file on disk, which became the first detector check.

---

## 4. Why the Classic Checks Miss It

GhostDebug does not use the APIs that normally create a debug port or debug object. Because of that, these checks are looking for state that GhostDebug never needed to create.

| Check | What it looks for | Expected result with GhostDebug |
|---|---|---|
| `IsDebuggerPresent` | PEB `BeingDebugged` | Not detected |
| `CheckRemoteDebuggerPresent` | Conventional debugging state | Not detected |
| `ProcessDebugPort` | Attached debug port | Not detected |
| `ProcessDebugObjectHandle` | Debug object handle | Not detected |
| `ProcessUsingVEH` | Whether the process uses VEH | Observable; purpose unknown |
| Executable-code comparison | An active `INT3` change | Observable while the breakpoint is present |

---

## 5. What Can I Realistically Detect?

My first detector design treated individual observations too strongly. A VEH flag, new DLL, executable allocation, or patched byte can all come from legitimate software, so the detector combines them. It has two levels of visibility:

- **Scan mode:** inspect what exists right now.
- **Watch mode:** take a baseline first, then report what changes.

A scan shows what exists; a baseline shows what appeared during the test.

### 5.1 Keep the classic checks as a control

I still collect `CheckRemoteDebuggerPresent`, `ProcessDebugPort`, `ProcessDebugObjectHandle`, and `ProcessDebugFlags` as controls and for comparison with WinDbg or x64dbg.

If the process cannot be opened or its architecture is unsupported, the tool stops instead of printing a clean result. “I could not read it” and “I read it and found nothing” are not the same outcome.

An unreadable module produces a warning and the detector continues with the others. If that warning appears, `No indicators observed` should not be read as a complete clean scan.

### 5.2 Read the PEB `ProcessUsingVEH` flag

I use `NtQueryInformationProcess(ProcessBasicInformation)` to obtain the target PEB address and `ReadProcessMemory` to read `CrossProcessFlags`.

On the native x64 Windows 11 build I tested, the field is at offset `0x50`, and bit 2 is `ProcessUsingVEH`:

```text
ProcessUsingVEH = (*(u32 *)(PEB + 0x50) & 0x4) != 0
```

The flag only tells me that the process uses VEH. It says nothing about which handler was registered or why it exists, so the detector treats it as inconclusive on its own.

There is another important catch: the PEB is an internal structure, and Microsoft warns that its layout can change. I record the Windows build and limit this experiment to the x64 Windows 11 layout I tested.

### 5.3 Record modules without trusting their names

I enumerate modules with `CreateToolhelp32Snapshot`, `Module32FirstW`, and `Module32NextW`. Module snapshots can race with loader changes, so the code retries `ERROR_BAD_LENGTH` a limited number of times.

I care about whether an image appeared after the baseline. Its path, base, and size go into the report, but its name has no effect on the verdict.

A new module is not suspicious by itself. Programs load DLLs all the time. It becomes more interesting when a newly decoded VEH callback points into it, or when it appears with a new code modification.

### 5.4 Look for private executable memory

Using `VirtualQueryEx`, I walk the process address space and record committed `MEM_PRIVATE` regions that are executable.

The scan can expose manually mapped code or generated stubs, but JIT runtimes and instrumentation tools create the same kind of memory. A new region is more interesting than one that was already present at startup.

### 5.5 Compare executable code with the file on disk

The byte comparison ended up being the most direct check. The detector parses each loaded PE file, finds executable sections, reads the matching memory from the target, and looks for this difference:

```text
memory byte == 0xCC && original file byte != 0xCC
```

A completely raw comparison would produce false differences because the Windows loader applies relocations and fills the import table. The parser therefore ignores base-relocation targets and IAT ranges described by the PE format.

Ignoring those ranges removes two common sources of expected differences. It does not cover every legitimate loader or runtime modification, and it assumes the file at the module path is the same image that was originally loaded.

I call the results **INT3 candidates**, not confirmed breakpoints. My code does not fully disassemble the instruction stream, and hotpatching or security products could also modify executable code. A candidate that appears after the baseline at the same time as VEH becomes active is much more convincing than a candidate from a single scan.

### 5.6 Enumerate and decode VEH callbacks

Callback enumeration took most of the development time. Windows exposes functions for adding and removing VEH callbacks, but none for listing them. Reading the list from another process meant relying on private ntdll implementation details.

On the Windows 11 25H2 build I tested, the process-wide handler lists are stored behind `LdrpVectorHandlerList`. Rather than hardcoding its address, the detector resolves it from the detector's local copy of ntdll, calculates its RVA, and applies that RVA to the target's ntdll base. The code verifies that the local and target images report the same `SizeOfImage`, but equal image sizes do not prove that the two ntdll builds are identical.

The resolver starts from `RtlRemoveVectoredExceptionHandler`, follows its jump to the internal implementation, and looks for the RIP-relative reference to the list:

```asm
ntdll!RtlRemoveVectoredExceptionHandler:
    xor edx, edx
    jmp ntdll!RtlpRemoveVectoredHandler

ntdll!RtlpRemoveVectoredHandler+0x1b:
    lea r12, [ntdll!LdrpVectorHandlerList]
```

For the x64 layout in this build, the exception-handler list head is at `LdrpVectorHandlerList + 0x08`. Each node is part of a doubly linked list, and its encoded callback is stored at offset `0x20`.

The detector walks the list twice and only accepts it if both reads match. It checks the forward and backward links, rejects cycles and invalid user-mode pointers, limits the maximum number of entries, decodes every callback, and verifies that the result points to committed executable memory. Finally, it maps the callback address to a loaded module when possible and records the memory type and protection. An address outside the module list is not necessarily private memory; it can also belong to a mapped region.

The callback address says much more than the `ProcessUsingVEH` bit because I can map it back to an image or memory region. The method is version-sensitive, so a failed resolver or list validation produces an unknown result instead of an empty list.

### 5.7 What about timing checks?

I considered timing as well, but ordinary instructions give the VEH debugger nothing to handle.

Timing an intentional exception might show extra delay from the handler and its communication path. The problem is noise from scheduling, virtual machines, power management, logging, and security software. I would treat timing only as supporting evidence, not as the main detector.

### 5.8 Turning the observations into a verdict

I wanted the output to show why it reached a verdict, so the program reports the observations alongside the label. Scan and watch mode use different rules because one describes a snapshot and the other describes a change.

#### Scan mode

| Current observation | Result |
|---|---|
| Conventional debugger state | High confidence |
| `ProcessUsingVEH` and an active `INT3` candidate | High confidence |
| A decoded callback in private executable memory | Suspicious |
| An active `INT3` candidate | Suspicious |
| `ProcessUsingVEH` and private executable memory | Suspicious |
| `ProcessUsingVEH` without stronger evidence | Inconclusive |
| A top-level required collection is unavailable and there is no stronger evidence | Unknown / partial collection |
| Private executable memory alone | No indicators observed under the current rules |
| All top-level checks complete and find nothing relevant | No indicators observed |

#### Watch mode

| Change from the original baseline | Result |
|---|---|
| Conventional debugger state appears | High confidence |
| A new callback points into a newly loaded module | High confidence |
| A new callback points into private executable memory | High confidence |
| `ProcessUsingVEH` changes from false to true with a new `INT3` candidate | High confidence |
| A new module and `INT3` candidate appear while `ProcessUsingVEH` is true | High confidence |
| A new callback or `INT3` candidate without a stronger transition | Suspicious |
| `ProcessUsingVEH` changes from false to true with a new private executable region | Suspicious |
| `ProcessUsingVEH` changes from false to true without a stronger transition | Inconclusive |
| A top-level required collection is unavailable and there is no stronger evidence | Unknown / partial collection |
| A new module or private executable region alone | No indicators observed under the current rules |
| No relevant change is observed | No indicators observed |

The labels rank the evidence the detector collected. `High confidence` means several changes line up with an attachment; it is not a claim that the callback's code has been identified as a debugger. A per-module PE warning also does not currently force an unknown verdict.

---

## 6. Building It in Rust

The project stayed small enough that I could trace each check from the CLI to the Windows call:

```text
veh-detector/
|-- Cargo.toml
|-- build-windows.sh
|-- src/
|   |-- main.rs       # Windows entry point and exit codes
|   |-- windows.rs    # collection, snapshots, CLI, JSON, and verdicts
|   `-- pe.rs         # PE parsing, code comparison, and parser tests
`-- test-targets/
    `-- benign-veh/
        |-- benign_veh.c
        `-- build.bat
```

The only direct Rust dependency is `windows-sys`:

```toml
[dependencies]
windows-sys = { version = "0.61.2", features = [
    "Win32_Foundation",
    "Win32_System_Diagnostics_Debug",
    "Win32_System_Diagnostics_ToolHelp",
    "Win32_System_LibraryLoader",
    "Win32_System_Memory",
    "Win32_System_SystemInformation",
    "Win32_System_Threading",
] }
```

### 6.1 Opening the target

The tool accepts either a PID or a process name:

```powershell
.\veh-detector.exe --pid 4242
.\veh-detector.exe scan --pid 4242
.\veh-detector.exe --name TestTarget.exe
```

It opens the process with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE` and uses `IsWow64Process2` to make sure both sides match the native x64 layout expected by the code.

I tested Windows 11 25H2 build 26200. The code currently tries the same PEB and private-list layout on builds 22000 and newer, which is a wider range than I have verified. The list validation is there to reject an unexpected layout, not to promise compatibility with every Windows 11 build.

The `PROCESS_VM_WRITE` right looks out of place in a scanner. Remote pointer decoding needs it when Windows queries the target's process cookie. The detector never calls `WriteProcessMemory`; the permission is present only because the query fails without it.

I wrapped native handles so Rust closes them automatically:

```rust
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0); }
    }
}
```

The remote-read helper rejects partial reads, and I use checked address arithmetic before building pointers.

### 6.2 Keeping “false” separate from “unknown”

Most collected values are optional:

```rust
struct Snapshot {
    captured_unix_ms: u128,
    process_uses_veh: Option<bool>,
    classic: ClassicDebugState,
    modules: Option<Vec<ModuleInfo>>,
    veh_handlers: Option<Vec<VehHandler>>,
    breakpoint_candidates: Option<Vec<BreakpointCandidate>>,
    private_executable_regions: Option<Vec<ExecutableRegion>>,
    warnings: Vec<String>,
}
```

`Some(false)` means the check worked and returned false. `None` means it failed or was unsupported. The JSON output uses `null` for the same distinction.

With this representation, a failed collector cannot look like a negative result.

### 6.3 Reading `ProcessUsingVEH`

The code first queries the PEB and then reads the flags:

```rust
fn query_process_using_veh(process: HANDLE) -> Result<bool, String> {
    let basic: ProcessBasicInformation =
        nt_query(process, PROCESS_BASIC_INFORMATION_CLASS)?;

    let address = (basic.peb_base_address as usize)
        .checked_add(PEB_CROSS_PROCESS_FLAGS_OFFSET_X64)
        .ok_or("PEB address overflow")?;

    let flags: u32 = read_value(process, address)?;
    Ok(flags & PROCESS_USING_VEH != 0)
}
```

### 6.4 Walking the private VEH list

The callback enumerator does four things:

1. resolves the private list location from the detector's local ntdll;
2. translates that location to the target using an RVA;
3. walks and validates the remote doubly linked list;
4. decodes each protected callback and maps it to its owning memory.

I dynamically resolve `RtlDecodeRemotePointer` from ntdll, with KernelBase and Kernel32 as fallback locations. The import failure that forced dynamic resolution is covered below; the double-read validation rejects a snapshot if registration or removal changes the list during collection.

### 6.5 The part that kept breaking

The callback reader broke in three different places before it worked. Each failure pointed to an assumption I had made about ntdll or the process handle.

The first version scanned the exported `RtlRemoveVectoredExceptionHandler` address for a reference to `LdrpVectorHandlerList`. On Windows 11 build 26200, the export is only a tiny wrapper that jumps backward to `RtlpRemoveVectoredHandler`. The expected instruction still existed, but it was in the internal function. I confirmed this in WinDbg and changed the resolver to follow the relative jump before scanning.

![WinDbg disassembly showing the jump to RtlpRemoveVectoredHandler and its reference to LdrpVectorHandlerList](/assets/img/veh-detection/windbg2.webp)

*Figure 3: `RtlRemoveVectoredExceptionHandler` jumps to the internal removal routine, where `LdrpVectorHandlerList` is referenced and the exception-handler list head is accessed at offset `0x08`.*

The `int 3` instructions after the unconditional jump are compiler padding in this ntdll build, not runtime breakpoint candidates introduced by GhostDebug.

The next build failed before `main()` with this message:

```text
The procedure entry point DecodeRemotePointer could not be located
```

The GNU import library used by `windows-sys` mapped `DecodeRemotePointer` to `api-ms-win-core-util-l1-1-1.dll`, but that API-set DLL does not export it. I removed the static import and resolved `RtlDecodeRemotePointer` dynamically from ntdll instead.

After that, the program reached the list but decoding failed with `STATUS_ACCESS_DENIED`. I first tried querying `ProcessCookie` directly and received the same error. The missing detail was the required access mask: this information class requires `PROCESS_VM_WRITE`. Adding that right to the process handle fixed decoding, even though the detector never writes to the process.

I kept these failures in the write-up because code built around private ntdll details needs to say exactly where it was tested and fail visibly when an assumption stops holding.

### 6.6 Comparing PE sections

`pe.rs` reads the DOS header, PE header, section table, relocation directory, and IAT directory. It does not try to be a complete PE library. It validates the header and section ranges it consumes and uses checked arithmetic for parser offsets. Unit tests cover truncated headers, optional-header directory bounds, IAT exclusions, and `DIR64` relocation exclusions.

For each executable section, the detector reads process memory in 64 KiB chunks. If it finds an in-memory `0xCC` where the original file contains another byte, it records:

- the virtual address;
- module name;
- section name;
- RVA;
- original byte.

The result list is capped so a strange or hostile target cannot make the detector grow memory forever.

### 6.7 Scan mode and watch mode

The command line exposes the scan and watch modes described in Section 5. Scan mode takes one snapshot:

```powershell
.\veh-detector.exe scan --pid 4242 --json scan.json
```

Watch mode takes its first snapshot as the baseline and compares later samples with it:

```powershell
.\veh-detector.exe watch --pid 4242 --interval-ms 1000
.\veh-detector.exe watch --pid 4242 --samples 30 --json watch.json
```

It looks for generic changes: `ProcessUsingVEH` changing from false to true, new modules, new decoded callbacks, new private executable regions, new `INT3` candidates, or conventional debugger state appearing. There are no GhostDebug filenames or pipe names in the detection rules.

The `--json` path is overwritten after every sample, so `watch.json` contains only the latest snapshot. The terminal output preserves the observed transitions, but the current JSON file is not an event history.

---

## 7. How I Tested It

I ran the detector in a FLARE-VM Windows 11 25H2 guest using native x64 binaries. Windows reported version `10.0.26200.8246`; the detector itself records only the base build, `26200`. I used GhostDebug's `TestTarget.exe` as the main target.

I started with a clean target, launched watch mode, and only then attached GhostDebug:

```powershell
.\veh-detector.exe watch --pid 244 --interval-ms 1000 --json watch.json
```

The detector has to start first because its opening sample becomes the baseline. During development I also used WinDbg to verify the internal ntdll reference and callback offsets. The conventional checks fired while WinDbg was attached and went clean again when only GhostDebug remained.

For a false-positive control, I wrote `benign-veh.exe`. It prints its PID, waits for Enter, registers a callback that only returns `EXCEPTION_CONTINUE_SEARCH`, then waits again before removing it. Figure 6 comes from separate scans before and after registration. Watch mode gives the registration a suspicious label because it saw a new callback appear, even though the program does no debugging.

Section 8 reports the results. Still on my test list are a renamed GhostDebug build, deliberately broken collection paths, and more Windows builds.

---

## 8. Results

The baseline was clean:

```text
PEB ProcessUsingVEH: false
Decoded VEH callbacks: 0
Active INT3 candidates: 0
Private executable regions: 0

Verdict: NO INDICATORS OBSERVED
```

During attachment, the detector first saw new modules and a private executable page. VEH became active on the next sample and the callback appeared. I shortened the terminal output below:

```text
Sample 10: HIGH CONFIDENCE
  [+] Module: ghostdebug-core.dll at 0x00007FFBD6DE0000
  [...] Two dependency-module lines omitted
  [+] VEH #1: 0x00007FFBD6DE1B00
      -> ghostdebug-core.dll, MEM_IMAGE, protection 0x20
  [!] Private executable region:
      0x000001EB56A10000-0x000001EB56A11000, protection 0x40

Verdict: HIGH CONFIDENCE
  - ProcessUsingVEH changed from false to true
  - 3 module(s) appeared
  - 1 decoded VEH callback appeared
  - 1 private executable region appeared
```

The other two images were the DLL's `libc++.dll` and `libunwind.dll` dependencies. I suspect the 4 KiB private RWX region was the DLL-path allocation: GhostDebug requests executable, writable memory for the path and does not release it after `LoadLibraryA` returns. I did not dump that page, so I cannot confirm its contents. The order still fits the source: the DLL loads before it registers the callback.

The callback address is at RVA `0x1B00` inside the newly loaded image:

```text
0x00007FFBD6DE1B00 - 0x00007FFBD6DE0000 = 0x1B00
```

That matches the `ghostdebug_core!debugger::exception_handler` location I had already seen with symbols in WinDbg. The detector did not need that symbol or the DLL name to reach its verdict. Its generic rule was that a decoded VEH callback appeared inside a module that was not present in the baseline.

No traditional debugger state appeared, and this run missed the active `INT3`. The new module and its callback were enough for the high-confidence transition anyway.

I then tested the code-comparison signal directly. `TestTarget.exe` printed `debug_this` at `0x7FF797131460`, and I armed a GhostDebug breakpoint at that address without executing it. A scan found the same location as `TestTarget.exe+0x1460` in `.text`: the file contained `0x48`, while process memory contained `0xCC`. `ProcessUsingVEH` was true, one callback was decoded, and the conventional debugger checks all remained false.

![TestTarget, GhostDebug, and the detector showing an armed INT3 breakpoint at TestTarget.exe plus RVA 0x1460](/assets/img/veh-detection/int3-detection.webp)

*Figure 4: A targeted scan catches the armed breakpoint before execution reaches it. The detector correlates the `0xCC` change with VEH state and a decoded callback, producing a high-confidence verdict.*

After I cleared the breakpoint with GhostDebug's `cl` command, the next scan found zero `INT3` candidates. The callback and private RWX allocation remained, so the verdict dropped from high confidence to suspicious. The candidate was following the patched byte, not merely the injected DLL.

![GhostDebug clearing the breakpoint and the detector reporting zero active INT3 candidates](/assets/img/veh-detection/int3-removed.webp)

*Figure 5: Clearing the breakpoint restores the original byte. The remaining VEH callback and private executable region still produce a suspicious result, but the `INT3` evidence is gone.*

The benign program gave me a useful control. Before registration, the scan was clean. After registration, it found `ProcessUsingVEH` and one `MEM_IMAGE` callback inside the existing executable, with no `INT3` candidates or private executable regions. A standalone scan labels that combination inconclusive.

![Detector results before and after a benign executable registers one vectored exception handler](/assets/img/veh-detection/benign-veh.webp)

*Figure 6: The handler is visible, but the scan has nothing connecting it to debugging.*

I then ran the same program under watch mode. The baseline had no callback. After I pressed Enter, `ProcessUsingVEH` changed from false to true and the callback appeared inside the existing executable. That earns a suspicious transition, but there is no `INT3`, private executable page, or new module tying it to debugging.

![Watch mode observing a benign executable register one vectored exception handler after a clean baseline](/assets/img/veh-detection/benign-veh-watch.webp)

*Figure 7: Watch mode catches the benign callback appearing after the baseline. The suspicious label comes from the change, not from what the handler does.*

---

## 9. False Positives

The verdict ranks correlated evidence, not intent. VEH is used by browsers, crash handlers, runtimes, overlays, accessibility software, anti-cheat products, EDR agents, and instrumentation tools. Private executable memory and modified executable bytes also have legitimate uses. The detector therefore avoids these shortcuts:

- treating `ProcessUsingVEH` as proof;
- treating every `0xCC` byte as a breakpoint;
- treating every new DLL as injected;
- trusting a filename as an identity;
- turning a failed read into a negative result.

Watch mode adds an order and time window to those observations, but does not eliminate false positives.

---

## 10. What This Approach Misses

### 10.1 Private callback-list internals

Because callback enumeration depends on private ntdll code and structure layouts, a Windows update could change the wrapper, list layout, or node offset. The validation should reject an unfamiliar layout and return unknown, but there is no stable API contract here.

Remote pointer decoding also requires `PROCESS_VM_WRITE` access to the target. A protected process or restrictive security descriptor can deny that access even when basic inspection succeeds.

### 10.2 No baseline means less confidence

Starting after attachment loses the timeline and leaves only a triage snapshot of the current VEH state, private executable memory, and active `INT3` candidates.

### 10.3 Manual mapping

A debugger could manually map its code instead of calling `LoadLibrary`, removing the normal module-list transition. The detector may see unusual memory around it, but it cannot identify what that memory does.

### 10.4 Different exception hooks

A tool could avoid a normal VEH registration and hook an exception-dispatch routine such as `KiUserExceptionDispatcher`. My detector does not check that path.

### 10.5 Breakpoint coverage

GhostDebug briefly restores the original instruction while single stepping, so a periodic scan can land in that window and miss the `0xCC`. The file comparison also misses hardware breakpoints, page-guard breakpoints, and software breakpoints in private or generated code. It can correlate a callback with a patched byte, but it does not inspect the callback deeply enough to show that one handles the other.

### 10.6 Snapshot and collection limits

Watch mode compares every sample with the original baseline and reports additions. It does not currently report handler removal, module unloads, or private-region disappearance. Registrations are compared by decoded callback address, so registering the same callback address twice is not represented as a second new handler.

If one module cannot be read, the detector records a warning and checks the rest. That warning does not currently force an `Unknown` verdict. Failures in process enumeration, module enumeration, or the address-space walk are top-level gaps and can produce `Unknown`. I still need finer completeness tracking for partially successful scans.

### 10.7 User-mode limits

A user-mode scanner cannot reliably inspect every protected process or defend itself against a hostile kernel component. Kernel debuggers are also outside the scope of this project.

---

## 11. What the Test Showed

GhostDebug kept `IsDebuggerPresent`, the debug port, and the debug object clean, but it still changed the target by loading a DLL, registering a VEH callback, leaving an executable private allocation, and replacing an instruction byte with `0xCC`. Correlating those changes made the attachment visible without treating any single observation as proof.

Callback enumeration provided the strongest evidence and the greatest fragility because it relies on undocumented ntdll behavior. That tradeoff is acceptable for this experiment, but a production detector would need broader Windows-version testing and finer collection-completeness tracking.

---

## Source Material

- [VEH Debugger Detector source code](https://github.com/3krup/veh-detector)
- [GhostDebug](https://github.com/VollRagm/ghostdebug)
