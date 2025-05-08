#include <linux/sched.h>

struct task_info {
    u64 time_ns;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(start, u32, u64);
BPF_HASH(task_info, u32, struct task_info);

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 prev_pid = args->prev_pid;
    u64 ts = bpf_ktime_get_ns();
    u64 *start_ts;
    struct task_info *info, zero = {};
    
    u32 curr_pid = args->next_pid;
    start.update(&curr_pid, &ts);
    
    if (prev_pid == 0)
        return 0;
    
    start_ts = start.lookup(&prev_pid);
    if (start_ts == 0)
        return 0;
    
    u64 delta = ts - *start_ts;
    
    info = task_info.lookup_or_try_init(&prev_pid, &zero);
    if (info) {
        info->time_ns += delta;
        bpf_probe_read_kernel(&info->comm, sizeof(info->comm), args->prev_comm);
    }
    
    return 0;
}