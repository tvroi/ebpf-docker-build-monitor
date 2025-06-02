#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>
#include <linux/ip.h>
#include <linux/skbuff.h>

struct conn_info_t {
    u64 pid_tgid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 proto;
    char comm[TASK_COMM_LEN];
    u32 len;
};

BPF_HASH(currsock, u64, struct sock *);
BPF_PERF_OUTPUT(conn_events);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    currsock.update(&pid_tgid, &sk);
    
    return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct sock **skpp;
    skpp = currsock.lookup(&pid_tgid);
    if (skpp == 0) {
        return 0;
    }
    
    if (ret != 0) {
        currsock.delete(&pid_tgid);
        return 0;
    }
    
    struct sock *skp = *skpp;
    u32 saddr = skp->__sk_common.skc_rcv_saddr;
    u32 daddr = skp->__sk_common.skc_daddr;
    u16 dport = skp->__sk_common.skc_dport;
    u16 sport = skp->__sk_common.skc_num;
    
    struct conn_info_t conn_info = {0};
    conn_info.pid_tgid = pid_tgid;
    conn_info.saddr = saddr;
    conn_info.daddr = daddr;
    conn_info.sport = sport;
    conn_info.dport = ntohs(dport);
    conn_info.proto = 6;
    conn_info.len = 0;
    
    bpf_get_current_comm(&conn_info.comm, sizeof(conn_info.comm));
    conn_events.perf_submit(ctx, &conn_info, sizeof(conn_info));
    
    currsock.delete(&pid_tgid);
    
    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
    if (sk == NULL)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct inet_sock *inet = (struct inet_sock *)sk;
    u32 saddr = inet->inet_saddr;
    u32 daddr = inet->inet_daddr;
    u16 sport = inet->inet_sport;
    u16 dport = inet->inet_dport;
    
    struct conn_info_t conn_info = {0};
    conn_info.pid_tgid = pid_tgid;
    conn_info.saddr = saddr;
    conn_info.daddr = daddr;
    conn_info.sport = ntohs(sport);
    conn_info.dport = ntohs(dport);
    conn_info.proto = 6;
    conn_info.len = size;

    bpf_get_current_comm(&conn_info.comm, sizeof(conn_info.comm));
    
    conn_events.perf_submit(ctx, &conn_info, sizeof(conn_info));
    
    return 0;
}

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (sk == NULL)
        return 0;
        
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct inet_sock *inet = (struct inet_sock *)sk;
    u32 saddr = inet->inet_saddr;
    u32 daddr = inet->inet_daddr;
    u16 sport = inet->inet_sport;
    u16 dport = inet->inet_dport;
    
    struct conn_info_t conn_info = {0};
    conn_info.pid_tgid = pid_tgid;
    conn_info.saddr = saddr;
    conn_info.daddr = daddr;
    conn_info.sport = ntohs(sport);
    conn_info.dport = ntohs(dport);
    conn_info.proto = 17;
    conn_info.len = len;
    
    bpf_get_current_comm(&conn_info.comm, sizeof(conn_info.comm));
    
    conn_events.perf_submit(ctx, &conn_info, sizeof(conn_info));
    
    return 0;
}

int kprobe__ping_v4_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk)
        return 0;
        
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    if (pid == 0)
        return 0;
    
    u32 saddr = sk->__sk_common.skc_rcv_saddr;
    u32 daddr = sk->__sk_common.skc_daddr;
    
    struct conn_info_t conn_info = {0};
    conn_info.pid_tgid = pid_tgid;
    conn_info.saddr = saddr;
    conn_info.daddr = daddr;
    conn_info.sport = 0;
    conn_info.dport = 8;
    conn_info.proto = 1;
    conn_info.len = len;
    
    bpf_get_current_comm(&conn_info.comm, sizeof(conn_info.comm));
    
    conn_events.perf_submit(ctx, &conn_info, sizeof(conn_info));
    
    return 0;
}

int kprobe__icmp_push_reply(struct pt_regs *ctx, struct sk_buff *skb, 
                         struct icmphdr *icmp_hdr, struct flowi4 *fl4)
{
    if (!skb || !fl4)
        return 0;
        
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    if (pid == 0)
        return 0;
    
    u32 saddr = fl4->saddr;
    u32 daddr = fl4->daddr;
    
    u32 len = skb->len;
    
    struct conn_info_t conn_info = {0};
    conn_info.pid_tgid = pid_tgid;
    conn_info.saddr = saddr;
    conn_info.daddr = daddr;
    conn_info.sport = 0;
    conn_info.dport = 0;
    conn_info.proto = 1;
    conn_info.len = len;
    
    bpf_get_current_comm(&conn_info.comm, sizeof(conn_info.comm));
    
    conn_events.perf_submit(ctx, &conn_info, sizeof(conn_info));
    
    return 0;
}