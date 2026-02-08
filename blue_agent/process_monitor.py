#!/usr/bin/python3
from bcc import BPF

# -----------------------------------------------------------
# 1. The C Code (Runs INSIDE the Kernel)
# -----------------------------------------------------------
# We are writing C code that will be compiled on the fly and 
# injected into the OS kernel.
# -----------------------------------------------------------
bpf_source = """
#include <uapi/linux/ptrace.h>

// This function runs every time 'execve' is called.
// 'execve' is the syscall used to start ANY new program.
int trace_execve(struct pt_regs *ctx) {
    // bpf_trace_printk is a helper to print to the debug pipe
    bpf_trace_printk("ALERT: A new process was just started!\\n");
    return 0;
}
"""

# -----------------------------------------------------------
# 2. The Python Code (Runs in User Space)
# -----------------------------------------------------------
print("[-] Compiling eBPF object...")
# Load the C code into the kernel
b = BPF(text=bpf_source)

# Attach the C function to the system call "execve"
# This is the "Hook"
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="trace_execve")

print("[-] Sentinel Active. Monitoring for 'execve' syscalls...")
print("[-] Press Ctrl+C to stop.")

# 3. Read the debug pipe endlessly
while True:
    try:
        # verify_fields=False ignores harmless warnings about formatting
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(f"[KERNEL ALERT] PID: {pid} | Message: {msg.decode()}")
    except KeyboardInterrupt:
        print("\n[!] Detaching...")
        exit()
    except Exception as e:
        pass
