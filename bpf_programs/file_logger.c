#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>

#define TASK_COMM_LEN 16

struct file_data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char fname[256];
    char operation[16];
    u8 is_dir;
};

struct fd_key_t {
    u32 pid;
    u32 fd;
};

BPF_HASH(active_opens, u64, struct file_data_t);

BPF_HASH(fd_info, struct fd_key_t, struct file_data_t);

BPF_PERCPU_ARRAY(tmp_storage, struct file_data_t, 1);

BPF_PERF_OUTPUT(file_events);

static inline u64 gen_tgid_fd(u32 tgid, u32 pid) {
    return ((u64)tgid << 32) | pid;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->filename);
    
    __builtin_memcpy(&data->operation, "open", 5);
    
    data->is_dir = (args->flags & O_DIRECTORY) ? 1 : 0;
    
    u64 key = gen_tgid_fd(data->pid, pid_tgid & 0xFFFFFFFF);
    active_opens.update(&key, data);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    if (args->ret >= 0) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = pid_tgid & 0xFFFFFFFF;
        u64 key = gen_tgid_fd(pid, tid);
        
        struct file_data_t *data = active_opens.lookup(&key);
        if (data != NULL) {
            struct fd_key_t fd_key = {
                .pid = pid,
                .fd = (u32)args->ret
            };
            
            fd_info.update(&fd_key, data);
            
            active_opens.delete(&key);
        }
    }
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    struct fd_key_t key = {
        .pid = pid,
        .fd = (u32)args->fd
    };
    
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    struct file_data_t *info = fd_info.lookup(&key);
    if (info != NULL) {
        __builtin_memcpy(data, info, sizeof(*data));
        
        __builtin_memcpy(&data->operation, "read", 5);
        
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        
        file_events.perf_submit(args, data, sizeof(*data));
    }
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    struct fd_key_t key = {
        .pid = pid,
        .fd = (u32)args->fd
    };
    
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    struct file_data_t *info = fd_info.lookup(&key);
    if (info != NULL) {
        __builtin_memcpy(data, info, sizeof(*data));
        
        __builtin_memcpy(&data->operation, "write", 6);
        
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        
        file_events.perf_submit(args, data, sizeof(*data));
    }
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    struct fd_key_t key = {
        .pid = pid,
        .fd = (u32)args->fd
    };
    
    fd_info.delete(&key);
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
    __builtin_memcpy(&data->operation, "unlink", 7);
    data->is_dir = 0;
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
    
    if (args->flag & AT_REMOVEDIR) {
        __builtin_memcpy(&data->operation, "rmdir", 6);
        data->is_dir = 1;
    } else {
        __builtin_memcpy(&data->operation, "unlink", 7);
        data->is_dir = 0;
    }
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mkdir) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
    __builtin_memcpy(&data->operation, "mkdir", 6);
    data->is_dir = 1;
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mkdirat) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
    __builtin_memcpy(&data->operation, "mkdir", 6);
    data->is_dir = 1;
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rmdir) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
    __builtin_memcpy(&data->operation, "rmdir", 6);
    data->is_dir = 1;
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->oldname);
    __builtin_memcpy(&data->operation, "rename", 7);
    data->is_dir = 0xFF;  
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->oldname);
    __builtin_memcpy(&data->operation, "rename", 7);
    data->is_dir = 0xFF; 
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->oldname);
    __builtin_memcpy(&data->operation, "rename", 7);
    data->is_dir = 0xFF;
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getdents64) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    struct fd_key_t key = {
        .pid = pid,
        .fd = (u32)args->fd
    };
    
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    struct file_data_t *info = fd_info.lookup(&key);
    if (info != NULL) {
        __builtin_memcpy(data, info, sizeof(*data));
        
        __builtin_memcpy(&data->operation, "readdir", 8);
        data->is_dir = 1;
        
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        
        file_events.perf_submit(args, data, sizeof(*data));
    }
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getdents) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    struct fd_key_t key = {
        .pid = pid,
        .fd = (u32)args->fd
    };
    
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    struct file_data_t *info = fd_info.lookup(&key);
    if (info != NULL) {
        __builtin_memcpy(data, info, sizeof(*data));
        
        __builtin_memcpy(&data->operation, "readdir", 8);
        data->is_dir = 1;  // This is definitely a directory operation
        
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        
        file_events.perf_submit(args, data, sizeof(*data));
    }
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->filename);
    __builtin_memcpy(&data->operation, "chmod", 6);
    data->is_dir = 0xFF;
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->filename);
    __builtin_memcpy(&data->operation, "chmod", 6);
    data->is_dir = 0xFF; 
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}