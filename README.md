# Arapuca

Process sandbox for Linux, macOS, and Windows providing
kernel-enforced isolation. On Linux: Landlock, seccomp BPF, cgroups v2,
and network namespaces. On macOS: Apple's Seatbelt (`sandbox-exec`)
with deny-default profiles. On Windows: AppContainers, Job Objects,
restricted tokens, and process mitigation policies. Available as a Rust
library (with C FFI) and a CLI binary.

Arapuca is designed for running **untrusted code** — even a fully
compromised subprocess is contained by OS-level restrictions that cannot
be bypassed from userspace.

## Features

### Linux

- **Landlock** filesystem restrictions (ABI v1-v5) — allowlist of
  readable and writable paths; optional `allow_exec` enforcement
  strips Execute from all paths except the target binary and its
  ELF interpreter
- **Seccomp BPF** syscall filtering — three-tier deny list (KILL for
  escape-critical syscalls, EPERM for probed/filtered syscalls, ENOSYS
  for clone3 fallback). Two profiles: strict (untrusted code) and
  baseline (trusted-but-isolated applications)
- **Cgroups v2** resource limits — memory, CPU, PIDs, OOM detection,
  usage telemetry
- **Network namespace** isolation — CLONE_NEWUSER + CLONE_NEWNET
  blocks all direct network access; automatic **proxy bridge** relays
  HTTP traffic through a Unix domain socket so standard tools
  (curl, git, npm) work via HTTP_PROXY. `--deny-network` mode
  captures DNS queries as audit events and responds with NXDOMAIN.
  `--audit-files` and `--audit-network` enable syscall-level
  auditing via seccomp user notification (`SECCOMP_RET_USER_NOTIF`),
  emitting structured NDJSON events for file access, process spawn,
  and network connections
- **PID namespace** isolation — `CLONE_NEWPID` prevents the sandboxed
  process from seeing or signaling host processes. Automatic when
  network namespace is active; opt out with `--no-pid-ns`
- **pidfd-based signaling** — `Process::signal()` uses
  `pidfd_send_signal` (Linux 5.3+) for race-free signal delivery,
  preventing PID recycling races. Falls back to `kill()` on older
  kernels
- **Micro-VM isolation** *(experimental)* (optional, `microvm`
  feature) — runs the
  subprocess inside a lightweight KVM virtual machine via libkrun.
  Strongest isolation: separate kernel, address space, and device
  model. Includes image management (`arapuca image pull/list/rm/setup`),
  Fedora and CentOS Stream cloud images out of the box, external
  provider protocol for other distros, auto-detection of partition
  layout and filesystem
  type from qcow2 images, SHA256 checksum verification on download,
  setup layers for caching pre-configured images (e.g., with tools
  pre-installed), cloud-init guest configuration with `write_files`
  support, COW overlays, and optional networking via passt with
  `--no-map-gw` to prevent guest access to host localhost.
  **Persistent VMs** *(experimental)* (`vm start/exec/stop`) — long-running VMs with
  interactive access via vsock, nonce-based authentication, TTY
  support with raw terminal mode and SIGWINCH forwarding, persistent
  overlay disks, and a guest agent injected via read-only virtiofs share

### macOS

- **Seatbelt** (`sandbox-exec`) — deny-default profile with explicit
  allows for filesystem, exec, and Unix domain sockets. Three network
  modes: allowed (baseline), proxy-only (when a CONNECT proxy is
  configured — blocks all TCP, allows only UDS to proxy), and denied
  (strict)
- **Path validation** — strict character allowlist prevents Seatbelt
  profile injection attacks
- **Memory monitor** — best-effort RSS polling (500ms) with SIGKILL
  on limit breach (no cgroups on macOS)
- **Parent-PID watchdog** — kills subprocess if parent dies (replaces
  Linux's `PR_SET_PDEATHSIG`)
- Skips `RLIMIT_AS` on Apple Silicon (causes immediate SIGKILL due
  to macOS virtual memory behavior)

### Windows

- **AppContainer** — deny-by-default filesystem and network isolation;
  only explicitly granted paths are accessible to the subprocess
- **Job Object** — memory, CPU, and PID limits with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (all processes killed when
  the parent exits or crashes)
- **Restricted token** — `DISABLE_MAX_PRIVILEGE` strips all privileges;
  Low Integrity level (S-1-16-4096) prevents writes to higher-integrity
  objects. Used as fallback when AppContainer is not active.
- **Process mitigation policies** — DEP, mandatory ASLR, high-entropy
  ASLR, heap terminate on corruption, strict handle checks, Win32k
  syscall disable, extension point disable, remote image load block
- **Child process restriction** — optional
  `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` blocks the subprocess
  from spawning its own children (when `allow_exec` is false)
- **UI restrictions** — blocks desktop, clipboard, display settings,
  global atoms, and exit-windows access
- **Explicit handle inheritance** —
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` ensures only stdio handles are
  inherited; no handle leak to the subprocess
- **DACL rollback** — original filesystem permissions are saved before
  granting AppContainer access and restored during cleanup

### All platforms

- **Resource limits** — memory, CPU, PIDs (POSIX rlimits on
  Linux/macOS; Job Objects on Windows)
- **Process lifecycle** — launch, wait, resource stats, cleanup
- **C FFI** — shared library with C header for integration from
  C/C++/Go/Python (`.so` on Linux, `.dylib` on macOS, `.dll` on
  Windows)
- **Fail-closed** — if any restriction fails to apply, the process
  exits before running the target command
- **Environment hardening** — dangerous variables (`ARAPUCA_*`,
  `LD_*`, `DYLD_*`, `.NET`/`COR_*` prefixes, interpreter injection
  vectors, Windows shell variables) are filtered before exec
- **Structured audit events** — optional, zero-cost-when-unused event
  emission via a caller-supplied sink. Covers the full sandbox lifecycle:
  which layers were applied or skipped, env filtering decisions,
  filesystem/network/seccomp policy, resource usage, and cleanup status.
  Enables compliance (SOC 2, FedRAMP AU-3), SIEM integration, and
  forensic reconstruction of sandbox posture

## Quick Start

### Binary

The simplest integration: wrap any command with `arapuca`.

```bash
# Build
cargo build --release

# Run a command with filesystem restrictions
ARAPUCA_READ_PATHS="/usr:/lib:/lib64:/bin:/etc:/dev" \
ARAPUCA_WRITE_PATHS="/tmp/workspace" \
./target/release/arapuca -- python3 agent.py

# The sandboxed process:
# - Can only read files under /usr, /lib, /bin, /etc, /dev
# - Can only write under /tmp/workspace
# - Cannot create network sockets (AF_INET/AF_INET6 blocked)
# - Cannot call ptrace, mount, or manipulate namespaces
# - Is killed if the parent process dies
```

### Process Sandbox (`arapuca run`)

Run a command in a process-level sandbox with user-friendly CLI flags.
Works on Linux, macOS, and Windows — the appropriate isolation
primitives are selected at compile time.

```bash
# Run a command with default sandboxing (system paths readable,
# private temp dir writable, everything else blocked)
arapuca run -- /bin/echo hello

# Grant read-only access to a project directory
arapuca run -v /home/user/project:ro -- ls /home/user/project

# Grant read-write access
arapuca run -v /home/user/workspace -- python3 build.py

# Pass environment variables (dangerous vars like LD_PRELOAD are filtered)
arapuca run --env MY_TOKEN=secret --env JIRA_URL=https://jira.example.com \
  -- python3 agent.py

# Resource limits and timeout
arapuca run --memory 2048 --cpus 200 --pids 256 --timeout 600 \
  -v /home/user/project:ro \
  -- python3 agent.py

# Selective HTTPS access (Linux only): network namespace isolates the
# process, then a CONNECT proxy tunnels traffic only to allowed hosts.
arapuca run \
  -v /home/user/project:ro \
  --allow-host us-east5-aiplatform.googleapis.com:443 \
  --allow-host oauth2.googleapis.com:443 \
  --env VERTEXAI_PROJECT=my-project \
  --timeout 600 --memory 3072 \
  -- claude --bare -p --model claude-sonnet-4-6

# The sandboxed process:
# - Can only read default system paths + explicitly granted -v paths
# - Can only write to its private temp dir (use -v /path for more)
# - Gets a minimal environment (HOME, TMPDIR, PATH, LANG) + --env vars
# - Is killed after --timeout seconds (SIGTERM, then SIGKILL after 5s)
# - Cannot override sandbox-managed env vars (HOME, TMPDIR, PATH, LANG)
# - /proc, /sys, /dev are NOT accessible by default (opt-in via -v)
# - With --allow-host: no direct network; HTTPS only to listed hosts
#   via CONNECT proxy (DNS rebinding protection, IP range validation)
```

| Flag | Description |
|------|-------------|
| `-v /path[:ro]` | Allow path access (read-write default, `:ro` for read-only) |
| `--cwd /path` | Set working directory (must be within a mount) |
| `--env KEY=VALUE` | Pass environment variable |
| `--timeout N` | Kill after N seconds |
| `--memory N` | Memory limit in MB |
| `--cpus N` | CPU percentage (200 = 2 cores) |
| `--pids N` | Max number of PIDs |
| `--task-id NAME` | Identifier for cgroup and audit |
| `--allow-host H:P` | Allow HTTPS to host:port or `*.domain:port` via CONNECT proxy (Linux) |
| `--deny-network` | Block all network; capture DNS queries as audit events (Linux) |
| `--seccomp MODE` | Seccomp profile: `strict` (default) or `baseline` |
| `--audit-files` | Emit file access and process spawn audit events (Linux) |
| `--audit-network` | Emit network connection audit events (Linux) |
| `--seccomp-debug` | Log blocked syscalls to stderr instead of killing (diagnostic) |
| `--no-pid-ns` | Disable PID namespace isolation |
| `--lpac` | Run as a Less Privileged AppContainer; may break binaries needing registry/DLL access outside the LPAC allowlist (Windows) |
| `-t, --tty` | Allocate a PTY for interactive programs |

### Micro-VM (requires `microvm` feature)

Run a command inside a lightweight KVM virtual machine:

```bash
# Build with micro-VM support
cargo build --release --features microvm

# Pull a Fedora cloud image (~500MB, cached for reuse)
./target/release/arapuca image pull fedora:42

# Pull a CentOS Stream image
./target/release/arapuca image pull centos:9
./target/release/arapuca image pull centos:10

# Run a command in a micro-VM
./target/release/arapuca vm run --image fedora:42 \
  -v /home/user/project:/home/agent/work \
  -- make test

# With networking, file injection, and timeout
./target/release/arapuca vm run --image fedora:42 \
  --cpus 4 --mem 4096 \
  -v /home/user/project:/home/agent/work \
  --write-file ./internal.repo:/etc/yum.repos.d/internal.repo \
  --net --timeout 600 \
  -- sh -c 'dnf install -y my-package && make test'

# The VM provides:
# - Separate kernel (hardware isolation via KVM)
# - Read-only/read-write volume mounts (-v host:guest[:ro])
# - Optional networking via passt (--net)
# - File injection via cloud-init (--write-file)
# - Signal forwarding (Ctrl-C → SIGTERM, second → SIGKILL)
# - Exit code 125 for infrastructure errors

# Create a setup layer with pre-installed tools
./target/release/arapuca image setup fedora:42 \
  --run 'dnf install -y git python3'

# Future vm run uses the setup layer — no install needed
./target/release/arapuca vm run --image fedora:42 \
  -- git --version

# Manage cached images
./target/release/arapuca image list
./target/release/arapuca image rm fedora:42

# Check for upstream image updates (downloads only if changed)
./target/release/arapuca image pull --check centos:9

# Force re-download regardless of cache
./target/release/arapuca image pull --force centos:9
```

### Persistent VMs

Start a long-running VM and attach to it later, like
`podman run -d` + `podman exec`:

```bash
# Start a persistent VM (returns immediately)
arapuca vm start --image fedora:42 --net --name myvm

# Execute commands in the running VM
arapuca vm exec myvm -- echo hello
arapuca vm exec myvm -- dnf install -y git
arapuca vm exec myvm -- git --version

# Interactive shell (TTY mode)
arapuca vm exec myvm -t -- /bin/bash -l

# List running and stopped VMs
arapuca vm list

# Stop a VM (graceful shutdown, falls back to SIGKILL)
arapuca vm stop myvm

# Restart — persistent state (installed packages, files) is preserved
arapuca vm start --name myvm

# Reset overlay to base image (discards all changes)
arapuca vm reset myvm

# Remove a stopped VM entirely
arapuca vm rm myvm

# Clean up stale state from crashed VMs
arapuca vm prune
```

Persistent VMs use vsock for host-guest communication (no SSH
needed). A guest agent binary (`arapuca-agent`) is injected via a
read-only virtiofs share and handles exec requests over a binary
framing protocol with nonce-based authentication. The agent binary
is built separately without libkrun:

```bash
cargo build --features vm-agent --bin arapuca-agent
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ARAPUCA_READ_PATHS` | Readable paths (`:` on Unix, `;` on Windows) |
| `ARAPUCA_WRITE_PATHS` | Writable paths (`:` on Unix, `;` on Windows) |
| `ARAPUCA_RLIMIT_AS` | Max virtual memory in bytes |
| `ARAPUCA_RLIMIT_NPROC` | Max number of processes |
| `ARAPUCA_RLIMIT_CPU` | Max CPU time in seconds |
| `ARAPUCA_RLIMIT_FSIZE` | Max file size in bytes |
| `ARAPUCA_RLIMIT_NOFILE` | Max open file descriptors |
| `ARAPUCA_WRAPPER` | Internal sentinel (set by library, required for wrapper path) |

All `ARAPUCA_*` variables are stripped from the environment before
exec — the sandboxed process cannot inspect its own configuration.

### Rust Library

```rust
use arapuca::platform::{Sandbox, new};

let sandbox = new()?;

let config = arapuca::Config {
    profile: arapuca::Profile {
        read_paths: vec!["/usr".into(), "/lib".into(), "/etc".into()],
        write_paths: vec!["/tmp/workspace".into()],
        max_memory_mb: 2048,
        max_pids: 256,
        max_cpu_pct: 200, // 2 cores
        max_file_size_mb: 512,
        max_open_files: 1024,
        use_netns: true,
        use_pidns: true,
        allow_exec: true,
        dns_capture: false,
        audit_file_access: true,
        audit_network: false,
        seccomp_profile: arapuca::SeccompProfile::Strict,
        ..Default::default()
    },
    socket_dir: "/tmp/sockets".into(),
    task_id: "task-42".into(),
    phase: "executing".into(),
    work_dir: Some("/tmp/workspace".into()),
    stdin: None,
    stdout: None,
    stderr: None,
    extra_fds: Vec::new(),
    network_proxy_socket: None,
    env: Vec::new(),
    audit_sink: None,
    audit_verbosity: arapuca::audit::AuditVerbosity::Standard,
    audit_principal: None,
    audit_correlation_id: None,
};

let mut process = sandbox.launch(&config, "/usr/bin/python3", &["agent.py"])?;
let status = process.wait()?;
let stats = process.resource_stats();
println!("peak memory: {} bytes", stats.memory_peak_bytes);
process.cleanup();
```

### C Library

Build the shared library and generate the header:

```bash
cargo build --release  # produces .so (Linux), .dylib (macOS), or .dll (Windows)
make header            # generates include/arapuca.h
```

```c
#include <arapuca.h>

struct arapuca_ArapucaProfile *p = arapuca_profile_new();
arapuca_profile_add_read_path(p, "/usr");
arapuca_profile_add_read_path(p, "/lib");
arapuca_profile_add_write_path(p, "/tmp/workspace");
arapuca_profile_set_memory_mb(p, 2048);
arapuca_profile_set_netns(p, true);

if (arapuca_apply(p) != 0) {
    fprintf(stderr, "sandbox failed: %s\n", arapuca_last_error());
    exit(1);
}

arapuca_profile_free(p);
execvp("python3", argv);  // now sandboxed
```

Link with `-larapuca -ldl -lpthread`.

## Security Model

### Threat Model

The sandboxed process is **fully untrusted**. Arapuca assumes the
process may be prompt-injected, exploit vulnerabilities, or actively
attempt to escape. The sandbox limits blast radius even in the worst
case.

### Defense Layers (Linux)

| Layer | Mechanism | What it prevents |
|-------|-----------|------------------|
| Landlock | Kernel filesystem MAC | Reading/writing files outside allowlist |
| Seccomp BPF | Syscall filter | ptrace, mount, namespace escape, kernel modules |
| Network namespace | CLONE_NEWNET | All direct network access (AF_INET/AF_INET6) |
| Proxy bridge | TCP-to-UDS relay | Enables HTTP_PROXY in netns via hardened child process |
| PID namespace | CLONE_NEWPID | Sandboxed process seeing/signaling host processes |
| Unotify audit | SECCOMP_RET_USER_NOTIF | File access, process spawn, and network audit trail |
| DNS capture | UDP port 53 interception | DNS exfiltration, provides audit trail of queries |
| Cgroups v2 | Resource limits | Memory exhaustion, fork bombs, CPU starvation |
| Rlimits | POSIX limits | Large file creation, process proliferation |
| Pdeathsig | PR_SET_PDEATHSIG | Orphan processes surviving parent crash |
| Setsid | Session detach | Signal propagation to host terminal |
| Env stripping | Remove ARAPUCA_* | Agent inspecting its own sandbox config |
| Micro-VM (opt-in) | KVM via libkrun | Kernel exploits, syscall attacks, full address space isolation |

### Defense Layers (macOS)

| Layer | Mechanism | What it prevents |
|-------|-----------|------------------|
| Seatbelt | sandbox-exec profile | Filesystem/network access outside allowlist |
| Rlimits | POSIX limits | Large file creation, process proliferation |
| Memory monitor | RSS polling (500ms) | Memory exhaustion (best-effort) |
| Parent watchdog | getppid polling (2s) | Orphan processes surviving parent crash |
| Setsid | Session detach | Signal propagation to host terminal |
| Env stripping | Remove ARAPUCA_* | Agent inspecting its own sandbox config |

### Defense Layers (Windows)

| Layer | Mechanism | What it prevents |
|-------|-----------|------------------|
| AppContainer | CreateAppContainerProfile | Filesystem/network access outside allowlist (deny-by-default) |
| Job Object | KILL_ON_JOB_CLOSE | Memory exhaustion, fork bombs, CPU starvation, orphan processes |
| Restricted token | DISABLE_MAX_PRIVILEGE + Low IL | Privilege escalation (fallback when AppContainer inactive) |
| Mitigations | PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY | DEP bypass, ASLR bypass, Win32k attacks, DLL injection |
| Child process restriction | MITIGATION_POLICY QWORD2 | Subprocess spawning children (when allow_exec=false) |
| UI restrictions | JOBOBJECT_BASIC_UI_RESTRICTIONS | Desktop, clipboard, display settings, global atoms access |
| Handle inheritance | PROC_THREAD_ATTRIBUTE_HANDLE_LIST | Handle leak to subprocess (only stdio inherited) |
| DACL rollback | Save/restore ACLs | Persistent permission changes surviving sandbox exit |
| Env stripping | Filter ARAPUCA_*, COMSPEC, __COMPAT_LAYER, etc. | Config inspection, shell injection, compat shim injection |

### Seccomp Filter (Linux only)

Three tiers with different responses (strict profile):

**Tier 1 — KILL_PROCESS** (45 syscalls, no legitimate use):
`ptrace`, `mount`, `umount2`, `chroot`, `pivot_root`, `unshare`,
`setns`, `personality`, `memfd_create`, `memfd_secret`,
`bpf`, `kexec_*`, `reboot`, kernel module syscalls, new mount API
(`fsopen`, `fsmount`, `fspick`, `fsconfig`, `move_mount`, `open_tree`,
`mount_setattr`), `pidfd_getfd`, `pidfd_send_signal`,
`process_vm_readv/writev`, `process_madvise`, `userfaultfd`, `kcmp`,
`landlock_*`, `swapon`, `swapoff`, `acct`, `add_key/request_key/keyctl`,
`quotactl*`, LSM self-attr.

**Tier 2 — EPERM** (argument-filtered): `symlinkat`, `linkat`,
`socket(AF_INET|AF_INET6)`, `perf_event_open`,
`prctl(PR_SET_PDEATHSIG)`, `prctl(PR_SET_DUMPABLE, non-zero)`,
`execveat(AT_EMPTY_PATH)`, `ioctl(TIOCSTI|TIOCLINUX)`,
`kill(pid <= 0)`, `tkill`, `clone(CLONE_NEW*)`.

**Tier 3 — ENOSYS** (force fallback): `clone3` and `io_uring_*`
return ENOSYS so glibc/Go falls back to `clone(2)` (where namespace
flags can be inspected by BPF) and libraries probe io_uring support
and fall back to regular I/O.

`socket(AF_UNIX)` is not filtered — needed for IPC with the host
(JSON-RPC, LLM proxy). The **baseline** profile blocks only
escape-critical syscalls (Tier 1) and uses EPERM for
argument-filtered rules, allowing network sockets, memfd, etc.

### Network Model

The sandboxed process has **zero direct IP access**. All network
traffic must flow through a host-side proxy via Unix domain sockets.

```
┌─────────────────────────────────────────────────┐
│  Host process                                   │
│                                                 │
│  ┌──────────┐   ┌──────────┐                    │
│  │ JSON-RPC │   │ LLM      │                    │
│  │ control  │   │ proxy    │───► external APIs  │
│  └────┬─────┘   └────┬─────┘                    │
│       │              │                          │
│   Unix socket    Unix socket                    │
│   (control.sock) (llm.sock)                     │
│       │              │                          │
├───────┼──────────────┼──────────────────────────┤
│       │              │    Sandbox boundary      │
│       ▼              ▼                          │
│  ┌─────────────────────────────────────────┐    │
│  │  Sandboxed process                      │    │
│  │                                         │    │
│  │  • AF_INET/AF_INET6 blocked (EPERM)     │    │
│  │  • AF_UNIX allowed (control + LLM only) │    │
│  │  • AGENT_NETWORK_PROXY env var          │    │
│  │    points to LLM socket path            │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

**How it works per platform:**

| | Linux | macOS | Windows |
|-|-------|-------|---------|
| Block IP | Seccomp returns `EPERM` for `socket(AF_INET/AF_INET6)`. Optionally `CLONE_NEWNET` removes all network interfaces. | Seatbelt `(deny default)` blocks all TCP/UDP. | AppContainer denies network by default. `internetClient` capability granted only when `use_netns` is false. |
| Allow Unix sockets | Seccomp does not filter `AF_UNIX` — passes through. | `(allow network-outbound (remote unix))` plus literal file access on each socket path. | Named pipes / Unix sockets accessible if DACL grants access. |
| Proxy socket delivery | `AGENT_NETWORK_PROXY` env var (not stripped). | Same. | Same. |

The `AGENT_NETWORK_PROXY` env var deliberately avoids the `ARAPUCA_`
prefix so it survives the wrapper binary's environment sanitization.
The host-side proxy can enforce allowlists, rate limits, and logging
on all outbound traffic — the sandboxed process cannot bypass it.

## Architecture

### Overview

Arapuca provides two interfaces:

- **Library** (`rlib` + `cdylib`): Rust API and C FFI for embedding
  sandbox enforcement into a host process. The library manages the full
  subprocess lifecycle — launch, wait, resource stats, cleanup.
- **Binary**: Three modes of operation:
  - `arapuca run [flags] -- cmd [args...]` — process-level sandbox
    with CLI flags, using the library's `Sandbox::launch()` trait for
    cross-platform dispatch (Linux/macOS/Windows)
  - `arapuca vm run` — micro-VM sandbox via libkrun (Linux only)
  - `arapuca -- cmd [args...]` — self-sandbox mode that applies
    restrictions to the current process then `execve()`s the target.
    Used internally by the library as a subprocess wrapper for
    Landlock/seccomp/rlimit enforcement

The library spawns sandboxed processes by composing platform-specific
isolation primitives. On Linux, the binary acts as an inner wrapper
(Landlock + seccomp + rlimits applied before exec). On macOS,
`sandbox-exec` provides the kernel policy and the binary applies only
rlimits. On Windows, `CreateProcessW` with an extended attribute list
applies all restrictions atomically at process creation — no wrapper
binary is needed.

### Platform Abstraction

The `Sandbox` trait defines the platform contract:

```rust
pub trait Sandbox: Send + Sync {
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str])
        -> Result<Process>;
    fn available(&self) -> Result<()>;
    fn netns_available(&self) -> bool;
    fn cgroups_available(&self) -> bool;
}
```

`platform::new()` returns the appropriate implementation at compile time
via `#[cfg(target_os)]`. There is no runtime platform detection.

### Sandbox Lifecycle

```
Library (host process)
│
├─ Validate inputs (task ID, cgroup paths)
├─ Create temp dir (HOME/TMPDIR for subprocess)
├─ [Linux]   Create cgroup, set limits
├─ [macOS]   Generate Seatbelt .sb profile
├─ [Windows] Create Job Object, set limits + UI restrictions
├─ [Windows] Create AppContainer profile, grant DACL access
│
├─ Spawn subprocess ───────────────────────────────┐
│   ├─ [Linux]   unshare --net (if netns)          │
│   ├─ [Linux]   arapuca binary wrapper            │
│   │            ├─ Apply Landlock (fs allowlist)  │
│   │            ├─ Apply seccomp (syscall filter) │
│   │            ├─ Apply rlimits                  │
│   │            ├─ Set PR_SET_PDEATHSIG           │
│   │            ├─ Strip ARAPUCA_* env            │
│   │            └─ execve(target)                 │
│   ├─ [macOS]   sandbox-exec -f profile.sb        │
│   │            └─ [arapuca wrapper for rlimits]  │
│   │                └─ execve(target)             │
│   ├─ [Windows] CreateProcessW with attributes:   │
│   │            ├─ PROC_THREAD_ATTRIBUTE_JOB_LIST │
│   │            ├─ HANDLE_LIST (stdio only)       │
│   │            ├─ MITIGATION_POLICY              │
│   │            └─ SECURITY_CAPABILITIES          │
│   │                (AppContainer SID)            │
│   └─ [Unix]    setsid                            │
│                                                  │
├─ [Linux]   Add PID to cgroup                     │
├─ [macOS]   Start memory monitor thread           │
├─ [macOS]   Start parent-PID watchdog thread      │
│                                                  │
├─ wait() ← blocks until subprocess exits ─────────┘
├─ resource_stats() ← read cgroup stats (Linux)
└─ cleanup() ← destroy cgroup/Job Object/AppContainer,
               restore DACLs, remove temp dir
```

### Security Invariants

These are non-negotiable. Any change that weakens them requires
explicit security review:

1. **Fail-closed** — if any sandbox layer fails to apply, the process
   exits non-zero. The subprocess never runs unsandboxed.
2. **PR_SET_NO_NEW_PRIVS** — called before Landlock and seccomp
   (Linux). Prevents privilege escalation via setuid binaries.
3. **Setsid** — subprocess detached from host terminal session (Unix).
4. **Cgroup path rejection** — `/sys/fs/cgroup` blocked in read/write
   paths to prevent the subprocess from manipulating its own limits.
5. **Task ID sanitization** — `^[a-zA-Z0-9-]+$`, max 128 chars.
   Prevents path traversal in cgroup and temp dir names.
6. **Env stripping** — `ARAPUCA_*` vars removed before exec so the
   subprocess cannot inspect its own sandbox configuration.
7. **Path validation (macOS)** — strict character allowlist for Seatbelt
   profile paths prevents profile injection attacks.
8. **Atomic Job assignment (Windows)** —
   `PROC_THREAD_ATTRIBUTE_JOB_LIST` assigns the Job Object during
   `CreateProcessW`, preventing any window where the process runs
   outside the Job.
9. **DACL restoration (Windows)** — filesystem permissions granted to
   the AppContainer SID are restored to their original state during
   cleanup, even on error paths.
10. **Kill-on-close (Windows)** — `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
    ensures all processes in the Job are killed if the parent crashes.
11. **Unotify supervisor before Landlock** — the seccomp user
    notification supervisor is forked before Landlock is applied, since
    it needs `/proc/<pid>/mem` access that Landlock intentionally blocks.

### Environment Variable Convention

| Prefix | Scope | Stripped before exec? |
|--------|-------|-----------------------|
| `ARAPUCA_*` | Sandbox config (paths, rlimits) | Yes |
| `AGENT_*` | Agent-facing config (proxy sockets) | No |

This separation prevents the bug found in the Go predecessor where
`SANDBOX_NETWORK_PROXY` was set by the library but stripped by the
binary along with all `SANDBOX_*` vars.

### `unsafe` Audit Scope

`#![deny(unsafe_op_in_unsafe_fn)]` is set crate-wide. Every `unsafe`
block has a `// SAFETY:` comment. Expected `unsafe` locations:

| File | Reason |
|------|--------|
| `ffi.rs` | FFI exports, pointer dereference (null-checked) |
| `rlimit.rs` | `prlimit64` / `setrlimit` (raw syscall) |
| `landlock.rs` | `libc::syscall` for ABI version probe |
| `seccomp.rs` | SIGSYS handler, signal setup, fork in tests |
| `cgroup.rs` | `libc::kill` for SIGKILL |
| `pidns.rs` | `unshare`, `fork`, `pipe2`, `_exit`, `waitpid` |
| `unotify.rs` | `ioctl` (seccomp notification), `fcntl`, `fork`, `pidfd_getfd` |
| `selfexec.rs` | `#[unsafe(no_mangle)]`, raw pointer dereference, `_exit`, `execve` |
| `wrapper.rs` | `libc::write`, `getrandom`, `prctl`, `execve` |
| `terminal.rs` | `tcgetattr`, `cfmakeraw`, `tcsetattr` |
| `process.rs` | `pidfd_send_signal`, `kill`, `waitpid`, `waitid` |
| `platform/linux.rs` | `pre_exec()` for setsid + pdeathsig |
| `platform/darwin/mod.rs` | `pre_exec()` for setsid, `kill()` for monitors |
| `platform/windows.rs` | Win32 API calls: `CreateProcessW`, `CreateJobObjectW`, `CreateRestrictedToken`, `SetTokenInformation`, `DuplicateHandle`, DACL/ACL operations, `NtSetInformationProcess` |
| `platform/fd.rs` | `fcntl`, `dup2`, `close` |
| `bridge.rs` | Netlink socket/send/recv for loopback, `OwnedFd::from_raw_fd` |
| `platform/microvm.rs` | `libc::fork`, krun_sys FFI calls, `libc::getrandom` |
| `platform/microvm_net.rs` | `libc::fcntl` (CLOEXEC), `libc::close`, `into_raw_fd` |
| `bin/arapuca.rs` | `libc::prctl`, `libc::execve`, `libc::fork`, `close_range`, `poll`, `read` |

## Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Build with micro-VM support (requires libkrun)
cargo build --features microvm

# Build the guest agent (no libkrun dependency)
cargo build --features vm-agent --bin arapuca-agent

# Static binary (musl, no libc dependency)
cargo build --release --target x86_64-unknown-linux-musl

# Run tests
cargo test

# Build with JSON audit callback support (FFI consumers)
cargo build --release --features serde

# Lint
cargo clippy -- -D warnings
cargo fmt --check

# Fuzz (requires nightly + cargo-fuzz)
cargo +nightly fuzz list
cargo +nightly fuzz run sanitize_task_id fuzz/seeds/sanitize_task_id
```

### Installing

```bash
# Build everything (release binaries, C library, man page) and install
make all
sudo make install

# Or install just the release binaries
make release
sudo make install

# Custom prefix (default is /usr/local)
make release
sudo make install PREFIX=/opt/arapuca

# Uninstall
sudo make uninstall
```

The `install` target installs whatever release artifacts were produced:
binaries to `$(PREFIX)/bin`, libraries to `$(PREFIX)/lib`, headers to
`$(PREFIX)/include`, and the man page to `$(PREFIX)/share/man/man1`.
Artifacts not found are silently skipped.

### Requirements

- Rust 1.85+ (edition 2024) with `cargo`, `rustfmt`,
  `clippy`
- `gcc`, `make`, `cbindgen`, `pandoc`
- **Linux**: kernel 5.13+ (Landlock) — degrades gracefully
  on older kernels; cgroups v2 with delegated controllers
  (for resource limits)
- **Linux (microvm feature)**: libkrun + libkrunfw,
  qemu-img, qemu-nbd (for image probing), OpenSSL
  development headers, and optionally passt (for VM
  networking). KVM (`/dev/kvm`) required
- **macOS**: `sandbox-exec` (ships with macOS, deprecated
  but functional through macOS 15)
- **Windows**: Windows 10+ (64-bit only) — AppContainers
  require user-mode profile creation (no admin required)

## Project Structure

```
src/
├── lib.rs              # Public API, re-exports
├── error.rs            # Error types (thiserror)
├── profile.rs          # Profile, Config, ResourceUsage
├── validate.rs         # Task ID sanitization, cgroup path rejection
├── landlock.rs         # Landlock filesystem restrictions (Linux)
├── seccomp.rs          # Seccomp BPF syscall filter (Linux)
├── rlimit.rs           # POSIX resource limits
├── cgroup.rs           # Cgroups v2 manager (Linux)
├── netns.rs            # Network namespace probe (Linux)
├── pidns.rs            # PID namespace isolation (Linux)
├── unotify.rs          # Seccomp user notification audit (Linux)
├── dns.rs              # DNS wire format parser for query capture
├── selfexec.rs         # Library-embedded sandbox trampoline (Linux)
├── wrapper.rs          # Shared wrapper utilities (PATH lookup, audit)
├── terminal.rs         # Terminal/PTY handling (Unix)
├── audit.rs            # Structured audit events, sink trait, context
├── bridge.rs           # Netns proxy bridge: loopback, relay, seccomp
├── env.rs              # Minimal environment, temp dirs, path utils
├── diskquota.rs        # Disk usage monitoring
├── process.rs          # Sandboxed process lifecycle
├── ffi.rs              # C ABI exports (+ audit callback behind serde)
├── images/
│   ├── mod.rs          # Image resolution dispatcher
│   ├── cache.rs        # Image cache (XDG_DATA_HOME/arapuca/images/)
│   ├── metadata.rs     # Image metadata (root device, fstype, checksums)
│   ├── fedora.rs       # Built-in Fedora cloud image provider
│   ├── centos.rs       # Built-in CentOS Stream cloud image provider
│   ├── provider.rs     # External provider protocol (arapuca-images-*)
│   ├── download.rs     # HTTP download with progress bar + SHA256
│   ├── probe.rs        # Auto-detect partition layout from qcow2
│   ├── setup.rs        # Setup layers (cached pre-configured overlays)
│   ├── overlay.rs      # COW qcow2 overlay creation (qemu-img)
│   └── cloudinit.rs    # Cloud-init NoCloud datasource generation
├── platform/
│   ├── mod.rs          # Sandbox trait + factory
│   ├── linux.rs        # Linux sandbox (Landlock + seccomp + cgroups)
│   ├── microvm.rs      # Micro-VM sandbox via libkrun (microvm feature)
│   ├── microvm_net.rs  # Passt networking for micro-VMs (microvm feature)
│   ├── darwin/
│   │   ├── mod.rs      # macOS sandbox (sandbox-exec + monitors)
│   │   └── darwin_profile.rs  # Seatbelt .sb profile generation
│   ├── windows.rs      # Windows sandbox (AppContainer + Job Object)
│   ├── fd.rs           # File descriptor management utilities
│   └── other.rs        # Degraded fallback (other Unix)
└── bin/
    └── arapuca.rs    # CLI binary (+ image/vm subcommands)

fuzz/
├── Cargo.toml          # cargo-fuzz manifest (libfuzzer-sys + arbitrary)
├── fuzz_targets/       # Fuzz targets with oracle assertions
│   ├── sanitize_task_id.rs
│   ├── validate_guest_path.rs
│   ├── validate_guest_permissions.rs
│   ├── filter_caller_env.rs
│   ├── sanitize_audit_string.rs
│   └── reject_cgroup_paths.rs
└── seeds/              # Initial seed corpora (escape-oriented)

include/
└── arapuca.h         # C header (generated by cbindgen)
```

## License

Apache-2.0
