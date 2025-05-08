#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char event[32];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_fork) {
    struct data_t data = {};
    data.pid = args->child_pid;
    data.ppid = args->parent_pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event, "sched_process_fork", sizeof("sched_process_fork"));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct data_t data = {};
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data.pid = task->pid;
    data.ppid = task->real_parent->pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event, "sched_process_exec", sizeof("sched_process_exec"));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct data_t data = {};
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data.pid = task->pid;
    data.ppid = task->real_parent->pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event, "sched_process_exit", sizeof("sched_process_exit"));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
    struct data_t data = {};
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data.pid = task->pid;
    data.ppid = task->real_parent->pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event, "sys_enter_clone", sizeof("sys_enter_clone"));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_clone) {
    struct data_t data = {};
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data.pid = task->pid;
    data.ppid = task->real_parent->pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event, "sys_exit_clone", sizeof("sys_exit_clone"));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}