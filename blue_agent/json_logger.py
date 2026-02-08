#!/usr/bin/python3
import json
import time
from bcc import BPF

# -----------------------------------------------------------
# 1. Configuration
# -----------------------------------------------------------
LOG_FILE = "/app/events.log" # We will save logs here

# -----------------------------------------------------------
# 2. The C Code (Kernel Hook)
# -----------------------------------------------------------
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# -----------------------------------------------------------
# 3. The Python Logger (User Space)
# -----------------------------------------------------------
print(f"[-] Sentinel JSON Logger Active. Writing to {LOG_FILE}...")

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    command = event.comm.decode()
    
    # FILTER: Ignore the noise (Docker internal processes)
    # We only want to log interesting things for the AI
    ignore_list = ["node", "sh", "runc", "dockerd", "containerd"]
    
    if command not in ignore_list:
        log_entry = {
            "timestamp": time.time(),
            "pid": event.pid,
            "uid": event.uid,
            "command": command,
            "alert_level": "INFO"
        }
        
        # Write to file immediately (append mode)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        
        print(f"[LOGGED] {command}")

# Initialize BPF
b = BPF(text=bpf_code)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="trace_execve")
b["events"].open_perf_buffer(handle_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
