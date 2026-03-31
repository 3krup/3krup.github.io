---
title: "Building a Linux Security Module in Rust: Blocking Ptrace with eBPF"
date: "2026-03-31"
tags:
    - [EBPF]
    - [Rust]
    - [Linux]
    - [Blue Team]
thumbnail: "/assets/img/thumbnail/lsmenf.jpg"
bookmark: true
---

> **Summary:** I built a custom LSM in Rust with Aya eBPF to control `ptrace`. The policy is simple: default deny, allow only trusted debugger binaries by `(inode, device)`, and log every denied attempt.

---

## 1. Introduction

### Why `ptrace` matters (and why attackers love it)
`ptrace` is one of Linux's most powerful process-control interfaces. Tools like `gdb` and `strace` rely on it for legitimate debugging. With `ptrace`, a process can inspect another process, stop it, read/write memory, and alter execution state.

That same power makes it a high-value abuse path. If an attacker can `ptrace` a target process, they may be able to:
- read secrets from memory (tokens, credentials, session material),
- inject code into trusted processes,
- tamper with control flow or registers,
- hide malicious behavior inside legitimate processes.

So the defensive goal is not "detect it later." The goal is to make unauthorized `ptrace` fail immediately.

### Approach
Instead of filtering in user space, I enforce policy at the kernel boundary with an eBPF LSM hook (`ptrace_access_check`). If the caller is not in an allowlist, the hook returns a negative errno and the kernel denies the action.

---

## 2. Background Concepts

### eBPF + LSM in practice
Modern kernels let eBPF programs attach to LSM hooks. These hooks run during security decisions, before the action is finalized. In this project, the hook checks who is making the `ptrace` request and decides allow/deny in real time.

### Why allowlist over blocklist
For high-risk primitives like `ptrace`, blocklists are weak: new tools, renamed binaries, and custom malware easily bypass static "known bad" signatures. An allowlist is stronger operationally:
- deny by default,
- explicitly allow only known debugger binaries,
- treat everything else as untrusted.

### Why `(inode, device)` instead of file path
Path checks are fragile in kernel security contexts:
- paths can change (rename/move),
- symlinks and bind mounts can alter what a path resolves to,
- namespaces can present different path views.

The code instead identifies the running executable using:
- **Inode (`i_ino`)**: file object identity within a filesystem,
- **Device ID (`s_dev`)**: which filesystem/device that inode belongs to.

Together they uniquely identify a file object on a mounted filesystem at that time. This is much more robust than path string matching.

---

## 3. What Inode and Device ID actually are

- **Inode:** Metadata record for a file object (permissions, ownership, timestamps, block pointers, etc.). File names are directory entries pointing to inodes.
- **Device ID:** Identifier of the filesystem/device superblock. Two files can share inode numbers across different devices, so inode alone is not enough.
- **Pairing both:** `(inode, device)` gives a stable identity for allowlisting a specific executable object.

Practical note: package upgrades or binary replacement often create a new inode, so allowlists must be refreshed when binaries change.

---

## 4. How the code works (logic walkthrough)

### Shared structs (`LSM-Enforcer-common/src/lib.rs`)
User space and eBPF share two key types:
- `BinaryId { inode, device }` for allowlist keys,
- `PtraceEvent` for blocked-attempt telemetry.

```rust
#[repr(C)]
#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub struct BinaryId {
    pub inode: u64,
    pub device: u64,
}
```

`PtraceEvent` is the ring-buffer event payload that user space reads and logs:

```rust
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PtraceEvent {
    pub tracer_pid: u32,
    pub target_pid: u32,
    pub uid: u32,
    pub parent_pid: u32,
    pub loginuid: u32,
    pub comm: [u8; 16],
}
```

So each denied event captures: who tried (`tracer_pid`/`comm`), who was targeted (`target_pid`), and identity context (`uid`, `parent_pid`, `loginuid`).

### Kernel hook (`LSM-Enforcer-ebpf/src/main.rs`)
The LSM program `block_ptrace` runs on `ptrace_access_check`:
1. Get caller context (`uid`, current task).
2. Read target task from hook args.
3. Walk current task -> `mm` -> `exe_file` -> `f_inode`.
4. Build `BinaryId { inode, device }` from `i_ino` + `i_sb->s_dev`.
5. Lookup in `ALLOWED_BINARIES` map.
6. If found, return `0` (allow).
7. If not found, emit `PtraceEvent` to ring buffer and return `-1` (`-EPERM`).

```rust
#[lsm(hook = "ptrace_access_check")]
pub fn block_ptrace(ctx: LsmContext) -> i32 {
    let uid = unsafe { bpf_get_current_uid_gid() } as u32;

    let target_task: *const task_struct = ctx.arg(0);
    let tgid = unsafe { (*target_task).tgid };

    let task = unsafe { bpf_get_current_task_btf() as *mut task_struct };
    if task.is_null() {
        return -1;
    }

    unsafe {
        let mm = (*task).mm;
        if mm.is_null() {
            return -1;
        }

        let exe_file = (*mm).__bindgen_anon_1.exe_file;
        if !exe_file.is_null() {
            let inode_ptr = (*exe_file).f_inode;
            if !inode_ptr.is_null() {
                let inode_num = (*inode_ptr).i_ino;
                let device_id = (*(*inode_ptr).i_sb).s_dev as u64;

                let id = BinaryId {
                    inode: inode_num,
                    device: device_id,
                };

                if ALLOWED_BINARIES.get(&id).is_some() {
                    return 0;
                }
            }
        }
    }

    report_event(tgid as u32, uid, task);
    -1
}
```

### Event reporting
`report_event` reserves a ring buffer slot, fills:
- tracer PID,
- target PID,
- UID,
- parent PID,
- login UID,
- process comm (`bpf_get_current_comm`),
then submits the event.

### User-space loader (`LSM-Enforcer/src/main.rs`)
The userspace app:
1. loads the compiled eBPF object,
2. loads + attaches the LSM program with BTF,
3. resolves allowlisted paths with `metadata()`,
4. inserts `(inode, device)` keys into `ALLOWED_BINARIES`,
5. polls the `EVENTS` ring buffer and logs blocked attempts.

```rust
let inode = metadata.ino();
let device = metadata.dev() as u64;
let binary_id = BinaryId { inode, device };
allowed_binaries.insert(&binary_id, &1, 0)?;
```

---

## 5. Implementation and expected behavior

### Policy behavior
- Trusted debugger binary in map -> `ptrace` succeeds.
- Any non-allowlisted executable issuing `ptrace` -> denied with `EPERM`.
- Denied attempts are logged with context for triage.

### Example flow
```bash
# Enforcer startup
sudo ./target/debug/LSM-Enforcer
[INFO LSM_Enforcer] Allowed ptrace from: /usr/bin/gdb (inode: 1965616, device: 38)
[INFO LSM_Enforcer] Allowed ptrace from: /usr/bin/strace (inode: 2224918, device: 38)
Waiting for Ctrl-C...

# Unauthorized tracer
./malicious_injector --pid 1024
malicious_injector: attach: ptrace(PTRACE_SEIZE, 1024): Operation not permitted
```

```bash
# Telemetry from enforcer
[INFO LSM_Enforcer] PTRACE BLOCKED - Tracer: malicious_injector (PID: 9876, UID: 1000), Target PID: 1024, Parent PID: 8888, LoginUID: 1000
```

PID meanings in this log:
- **Tracer PID**: the process trying to call `ptrace` (the one being blocked).
- **Target PID**: the process that tracer tried to inspect/control.
- **Parent PID**: the parent process of the tracer process.

This gives immediate prevention plus useful audit signals, without relying on post-facto detection.

---

## Conclusion

`ptrace` is necessary for observability and debugging, but it is also a powerful abuse primitive. Enforcing an allowlist at the LSM layer gives strong control where it matters: inside the kernel security path.

Using Rust + Aya also keeps development ergonomic: shared typed structs, a small eBPF program, and a clean async userspace event loop.

If you deploy this approach, treat allowlist management as a lifecycle task (binary updates, package changes, immutable images, etc.) so trusted tooling stays usable while unauthorized tracing stays blocked.

### Source Code

[Full source code for the LSM-Enforcer on GitHub](https://github.com/3krup/LSM-Enforcer)