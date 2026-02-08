#!/usr/bin/python3
from bcc import BPF

# -----------------------------------------------------------
# 1. The C Code (Kernel Space)
# -----------------------------------------------------------
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Define a data structure to save information
struct data_t {
    u32 pid;
    char comm[16]; // The name of the program (e.g., "nmap", "python")
};

// Create a "Performance Buffer" to send data to Python fast
BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx) {
    struct data_t data = {};

    // 1. Get the Process ID
    data.pid = bpf_get_current_pid_tgid() >> 32;

    // 2. Get the Command Name (the program name)
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 3. Submit the data to the buffer
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# -----------------------------------------------------------
# 2. The Python Code (User Space)
# -----------------------------------------------------------
b = BPF(text=bpf_code)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="trace_execve")

print("[-] Sentinel Advanced: capturing command names...")

# This function processes the data sent from C
def print_event(cpu, data, size):
    event = b["events"].event(data)
    
    # FILTER: We can ignore standard system noise if we want
    # For now, let's print everything to see it working
    print(f"[TRACKING] PID: {event.pid} | Command: {event.comm.decode()}")

# Connect the "print_event" function to the buffer
b["events"].open_perf_buffer(print_event)

while True:
    try:
        # Poll the buffer for new events
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
