# Vault Extension: Advanced RHEL Containment

**Status:** Draft / Planned
**Target Component:** RHEL 9 Desktop Server (Backup Target)
**Risk Addressed:** T-06 (RHEL Receiver Compromise via Application Bug), Zero-Day RCE in `rest-server` or `net/http` stack.

## 1. Overview

While the canonical Vault architecture isolates the `rest-server` receiver in a rootless, read-only Podman container with SELinux boundaries, an advanced attacker who discovers an RCE vulnerability in `rest-server` might still attempt to exploit it. 

This extension applies hyper-restrictive containment policies that assume the application process is already compromised, severely limiting post-exploitation lateral movement and privilege escalation.

## 2. Advanced Containment Policies

### 2.1. Network Namespace Isolation (`--network=none`)

**Problem:** By default, containers are attached to a bridge network or use host port forwarding, giving a compromised process access to a full TCP/IP stack to scan internal network segments or communicate externally.

**Solution:**
The `rest-server` containers will be launched with `--network=none`. The container will have no network interfaces other than `loopback`. 

**Implementation:**
- Caddy (running on the host/namespace) will communicate with `rest-server` via a **Unix Domain Socket** instead of a TCP port.
- The socket file will be bind-mounted into the container.
- Restic traffic is terminated at Caddy (TLS), passed via Unix Socket to the container, isolating the container completely from IP routing.

### 2.2. Custom Seccomp Profile

**Problem:** Default Docker/Podman seccomp profiles allow around 300+ system calls. A compromised process can use unused system calls (like `ptrace`, `unshare`, `bpf`) to attempt kernel exploits.

**Solution:**
A strict whitelist seccomp profile (`vault-rest-server-seccomp.json`) will be applied, allowing only the absolute minimum syscalls required by the Go `rest-server` binary.

**Implementation:**
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "openat", "close", "fstat", "lseek",
        "mmap", "mprotect", "munmap", "brk",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "futex", "nanosleep",
        "socket", "bind", "listen", "accept4", "epoll_wait", "epoll_ctl", "epoll_create1",
        "clone", "execve", "exit", "exit_group"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```
*(Note: `socket` is restricted to `AF_UNIX` if possible via arg filtering, further reducing the attack surface).*

### 2.3. Filesystem Hardening

**Problem:** If the attacker achieves RCE, they might try to drop a secondary payload (e.g., a reverse shell binary or script) into `/tmp` or another writable directory.

**Solution:**
- `--read-only`: The container's root filesystem will be strictly read-only.
- `--tmpfs /tmp:rw,noexec,nosuid,size=64m`: The temporary directory will be mounted as a memory-backed file system with the `noexec` flag. Even if an attacker drops a payload here, the Linux kernel will refuse to execute it.
- Only the specific `/data` repository path is bind-mounted with write permissions.

### 2.4. Caddy Response Size Limit

**Problem:** If the RHEL host is compromised or the `rest-server` is manipulated, an attacker might try to send an oversized response payload to the device during a connection to exploit a parsing bug in `restic` or exhaust memory.

**Solution:**
A strict constraint in Caddy limits the maximum `Content-Length` of any response to 128 MB (restic pack files are usually around 16-32 MB).

**Implementation:**
Add the following rule to the Caddyfile for both the PC and Phone virtual hosts:

```caddyfile
@oversized_response {
    expression {http.response.header.Content-Length} > 134217728
}
handle @oversized_response {
    respond "Response too large" 502
}
```

## 3. Launch Configuration (systemd)

When this extension is enabled, the `vault-pc-rest.service` ExecStart line changes to:

```ini
ExecStart=/usr/bin/podman run \
  --name vault-pc-rest \
  --replace --rm \
  --read-only \
  --security-opt seccomp=/etc/vault-rhel/vault-rest-server-seccomp.json \
  --security-opt no-new-privileges \
  --network=none \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v /var/lib/vault-rhel/repos/pc:/data:Z \
  -v /var/lib/vault-rhel/sockets/pc:/sockets:Z \
  docker.io/restic/rest-server:latest \
  --append-only --no-auth --path /data --listen unix:///sockets/rest-server.sock
```

## 4. Impact on Operations

This extension introduces extreme rigidity. If a future update to `rest-server` or the Go runtime introduces a new standard library requirement (e.g., a new syscall for memory allocation or networking), the container will crash immediately with a `SIGSYS` signal. Operations must be prepared to update the seccomp profile during maintenance windows.
