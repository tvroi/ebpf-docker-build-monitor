#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define TASK_COMM_LEN 16

struct file_data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char fname[256];
    char operation[16];
};

struct fd_key_t {
    u32 pid;
    u32 fd;
};

BPF_HASH(active_opens, u64, struct file_data_t, 1024);

BPF_HASH(fd_info, struct fd_key_t, struct file_data_t, 4096);

BPF_PERCPU_ARRAY(tmp_storage, struct file_data_t, 1);

BPF_PERF_OUTPUT(file_events);

static inline u64 gen_tgid_pid(u32 tgid, u32 pid) {
    return ((u64)tgid << 32) | pid;
}

static inline void copy_file_data(struct file_data_t *dest, struct file_data_t *src) {
    dest->pid = src->pid;
    __builtin_memcpy(dest->comm, src->comm, TASK_COMM_LEN);
    __builtin_memcpy(dest->fname, src->fname, 256);
    __builtin_memcpy(dest->operation, src->operation, 16);
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = pid_tgid & 0xFFFFFFFF;
    
    data->pid = tgid;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->filename) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->filename);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->filename);
        }
    } else {
        data->fname[0] = '\0';
    }
    
    __builtin_memcpy(&data->operation, "open", 5);
    
    u64 key = gen_tgid_pid(tgid, pid);
    active_opens.update(&key, data);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_truncate) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->path) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->path);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->path);
        }
    }
    
    __builtin_memcpy(&data->operation, "truncate", 9);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_ftruncate) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    
    struct fd_key_t key = {};
    key.pid = tgid;
    key.fd = (u32)args->fd;
    
    struct file_data_t *info = fd_info.lookup(&key);
    if (!info) {
        return 0;
    }
    
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data) {
        return 0;
    }
    
    copy_file_data(data, info);
    
    __builtin_memcpy(&data->operation, "truncate", 9);
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    if (args->ret < 0) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = pid_tgid & 0xFFFFFFFF;
    u64 key = gen_tgid_pid(tgid, pid);
    
    struct file_data_t *stored_data = active_opens.lookup(&key);
    if (stored_data) {
        struct fd_key_t fd_key = {};
        fd_key.pid = tgid;
        fd_key.fd = (u32)args->ret;
        
        fd_info.update(&fd_key, stored_data);
        
        active_opens.delete(&key);
    }
    
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_open) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = pid_tgid & 0xFFFFFFFF;
    
    data->pid = tgid;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->filename) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->filename);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->filename);
        }
    } else {
        data->fname[0] = '\0';
    }
    
    __builtin_memcpy(&data->operation, "open", 5);
    
    u64 key = gen_tgid_pid(tgid, pid);
    active_opens.update(&key, data);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_open) {
    if (args->ret < 0) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = pid_tgid & 0xFFFFFFFF;
    u64 key = gen_tgid_pid(tgid, pid);
    
    struct file_data_t *stored_data = active_opens.lookup(&key);
    if (stored_data) {
        struct fd_key_t fd_key = {};
        fd_key.pid = tgid;
        fd_key.fd = (u32)args->ret;
        
        fd_info.update(&fd_key, stored_data);
        active_opens.delete(&key);
    }
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    
    if (args->fd <= 2) {
        return 0;
    }
    
    struct fd_key_t key = {};
    key.pid = tgid;
    key.fd = (u32)args->fd;
    
    struct file_data_t *info = fd_info.lookup(&key);
    if (!info) {
        return 0;
    }
    
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data) {
        return 0;
    }
    
    copy_file_data(data, info);
    
    __builtin_memcpy(&data->operation, "read", 5);
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    
    if (args->fd <= 2) {
        return 0;
    }
    
    struct fd_key_t key = {};
    key.pid = tgid;
    key.fd = (u32)args->fd;
    
    struct file_data_t *info = fd_info.lookup(&key);
    if (!info) {
        return 0;
    }
    
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data) {
        return 0;
    }
    
    copy_file_data(data, info);
    
    __builtin_memcpy(&data->operation, "write", 6);
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    
    if (args->fd <= 2) {
        return 0;
    }
    
    struct fd_key_t key = {};
    key.pid = tgid;
    key.fd = (u32)args->fd;

    struct file_data_t *info = fd_info.lookup(&key);
    if (info) {
        u32 zero = 0;
        struct file_data_t *data = tmp_storage.lookup(&zero);
        if (data) {
            copy_file_data(data, info);
            __builtin_memcpy(&data->operation, "close", 6);
            bpf_get_current_comm(&data->comm, sizeof(data->comm));
            
            file_events.perf_submit(args, data, sizeof(*data));
        }
    }
    
    fd_info.delete(&key);
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getdents64) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    
    struct fd_key_t key = {};
    key.pid = tgid;
    key.fd = (u32)args->fd;
    
    struct file_data_t *info = fd_info.lookup(&key);
    if (!info) {
        return 0;
    }
    
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data) {
        return 0;
    }
    
    copy_file_data(data, info);
    
    __builtin_memcpy(&data->operation, "readdir", 8);
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getdents) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    
    struct fd_key_t key = {};
    key.pid = tgid;
    key.fd = (u32)args->fd;
    
    struct file_data_t *info = fd_info.lookup(&key);
    if (!info) {
        return 0;
    }
    
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data) {
        return 0;
    }
    
    copy_file_data(data, info);
    
    __builtin_memcpy(&data->operation, "readdir", 8);
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->pathname) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
        }
    }
    
    __builtin_memcpy(&data->operation, "unlink", 7);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->pathname) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
        }
    }
    
    __builtin_memcpy(&data->operation, "unlink", 7);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->oldname) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->oldname);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->oldname);
        }
    }
    
    __builtin_memcpy(&data->operation, "rename", 7);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->oldname) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->oldname);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->oldname);
        }
    }
    
    __builtin_memcpy(&data->operation, "rename", 7);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->oldname) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->oldname);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->oldname);
        }
    }
    
    __builtin_memcpy(&data->operation, "rename", 7);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->filename) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->filename);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->filename);
        }
    }
    
    __builtin_memcpy(&data->operation, "chmod", 6);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->filename) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->filename);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->filename);
        }
    }
    
    __builtin_memcpy(&data->operation, "chmod", 6);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mkdir) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->pathname) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
        }
    }
    
    __builtin_memcpy(&data->operation, "mkdir", 6);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mkdirat) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->pathname) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
        }
    }
    
    __builtin_memcpy(&data->operation, "mkdir", 6);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rmdir) {
    u32 zero = 0;
    struct file_data_t *data = tmp_storage.lookup(&zero);
    if (!data)
        return 0;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (args->pathname) {
        int ret = bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
        if (ret < 0) {
            bpf_probe_read_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
        }
    }
    
    __builtin_memcpy(&data->operation, "rmdir", 6);
    
    file_events.perf_submit(args, data, sizeof(*data));
    
    return 0;
}
