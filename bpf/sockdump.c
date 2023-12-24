/**
 * SPDX-License-Identifier: Dual BSD/GPL
 * Copyright 2023 Leon Hwang.
 */

#include "vmlinux.h"

#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"

extern int LINUX_KERNEL_VERSION __kconfig;

#define TASK_COMM_LEN 16
#define UNIX_PATH_MAX 108

#define SS_MAX_SEG_SIZE (1024 * 50)
#define SS_MAX_SEGS_PER_MSG 10

#define SS_PACKET_F_ERR 1

#define SOCK_PATH_OFFSET    \
    (offsetof(struct unix_address, name) + offsetof(struct sockaddr_un, sun_path))

struct config {
    __u32 pid;
    __u32 seg_size;
    __u32 segs_per_msg;
    char sock_path[UNIX_PATH_MAX];
};

static const volatile struct config CONFIG = {
    .pid = 0,
    .seg_size = SS_MAX_SEG_SIZE,
    .segs_per_msg = SS_MAX_SEGS_PER_MSG,
    .sock_path = "/tmp/sockdump.sock",
};

#define cfg ((const volatile struct config *) &CONFIG)

struct packet {
    __u32 pid;
    __u32 peer_pid;
    __u32 len;
    __u32 flags;
    char comm[TASK_COMM_LEN];
    char path[UNIX_PATH_MAX];
    char data[SS_MAX_SEG_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct packet);
    __uint(max_entries, 1024);
} packets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

static __always_inline bool
__is_kernel_ge_6_0_0(void)
{
    return LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 0, 0);
}

static __always_inline bool
__is_str_prefix(const char *str, const char *prefix, int siz)
{
    for (int i = 0; i < siz && prefix[i]; i++)
        if (str[i] != prefix[i])
            return false;

    return true;
}

static __noinline bool
__is_path_matched(__u64 *path)
{
    __u64 *sock_path = (__u64 *) cfg->sock_path;
    int i;

    // 1. Use __u64 to reduce iterations.
    // 2. Use __is_str_prefix() to match the prefix of the path.

    for (i = 0; i < UNIX_PATH_MAX / 8 && sock_path[i]; i++)
        if (path[i] != sock_path[i])
            return __is_str_prefix((const char *) &path[i],
                                   (const char *) &sock_path[i], 8);

    if (i == UNIX_PATH_MAX / 8)
        return __is_str_prefix((const char *) &path[i],
                               (const char *) &sock_path[i], 4);

    return true;
}

static __always_inline bool
match_path_of_usk(struct unix_sock *usk, __u64 *path)
{
    struct unix_address *addr;
    __u8 one_byte = 0;
    char *sock_path;

    // Skip current capture if addr->len is zero.

    addr = BPF_CORE_READ(usk, addr);
    if (!BPF_CORE_READ(addr, len))
        return false;

    // 1. Use offset instead of BPF_CORE_READ() to get the address of the path.
    // 2. Check if it's "@/path/to/unix.sock".

    sock_path = (char *) addr + SOCK_PATH_OFFSET;
    bpf_probe_read_kernel(&one_byte, 1, sock_path);
    if (one_byte)
        bpf_probe_read_kernel_str(path, UNIX_PATH_MAX, sock_path);
    else
        bpf_probe_read_kernel_str(path, UNIX_PATH_MAX, sock_path + 1);

    return __is_path_matched(path);
}

static __always_inline bool
__is_sock_path_matched(struct unix_sock *usk, __u64 *path)
{
    return usk && match_path_of_usk(usk, path);
}

static __always_inline void
collect_data(void *ctx, struct packet *pkt, char *buf, __u32 len)
{
    __u32 seg_size = cfg->seg_size, n;

    pkt->flags = 0;
    pkt->len = len;

    // It's necessary to check the maximum size of the segment. Otherwise, the
    // verifier will complain about the out-of-bound access.

    n = len > seg_size ? seg_size : len;
    if (n < SS_MAX_SEG_SIZE)
        bpf_probe_read(&pkt->data, n, buf);
    else
        bpf_probe_read(&pkt->data, SS_MAX_SEG_SIZE, buf);

    pkt->data[n < SS_MAX_SEG_SIZE ? n : SS_MAX_SEG_SIZE - 1] = '\0';
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, pkt, sizeof(*pkt));
}

static __noinline int
__usk_sendmsg(void *ctx, struct socket *sock, struct msghdr *msg, size_t len)
{
    struct unix_sock *usk, *peer;
    const struct iovec *iov;
    struct upid numbers[1];
    struct iov_iter *iter;
    struct packet *pkt;
    __u64 *path, nsegs;
    __u32 n, pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid && cfg->pid != pid)
        return 0;

    n = bpf_get_smp_processor_id();
    pkt = bpf_map_lookup_elem(&packets, &n);
    if (!pkt)
        return 0;

    path = (__u64 *) pkt->path;

    usk = bpf_skc_to_unix_sock(sock->sk);
    peer = usk ? bpf_skc_to_unix_sock(usk->peer) : NULL;
    if (!__is_sock_path_matched(usk, path) &&
        !__is_sock_path_matched(peer, path))
        return 0;

    pkt->pid = pid;
    bpf_get_current_comm(&pkt->comm, sizeof(pkt->comm));
    BPF_CORE_READ_INTO(&numbers, sock, sk, sk_peer_pid, numbers);
    pkt->peer_pid = numbers[0].nr;

    iter = &msg->msg_iter;

    if (__is_kernel_ge_6_0_0() && BPF_CORE_READ(iter, iter_type) == ITER_UBUF) {
        collect_data(ctx, pkt, BPF_CORE_READ(iter, ubuf), len);

        return 0;
    }

    if ((__is_kernel_ge_6_0_0() &&
            (BPF_CORE_READ(iter, iter_type) != ITER_IOVEC ||
             BPF_CORE_READ(iter, iov_offset) != 0)) ||
        BPF_CORE_READ(iter, iov_offset) != 0) {
            pkt->len = len;
            pkt->flags = SS_PACKET_F_ERR;

            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, pkt, sizeof(*pkt));

            return 0;
    }

    iov = (typeof(iov)) BPF_CORE_READ(iter, kvec);

    n = cfg->segs_per_msg > SS_MAX_SEGS_PER_MSG ? SS_MAX_SEGS_PER_MSG : cfg->segs_per_msg;
    nsegs = BPF_CORE_READ(iter, nr_segs);
    for (int i = 0; i < SS_MAX_SEGS_PER_MSG; i++) {
        if (i >= nsegs || i >= n)
            break;

        collect_data(ctx, pkt, BPF_CORE_READ(iov, iov_base),
                     BPF_CORE_READ(iov, iov_len));

        iov++;
    }

    return 0;
}

static __always_inline int
__kprobe_unix_sendmsg(struct pt_regs *ctx)
{
    struct socket *sock = (void *) PT_REGS_PARM1(ctx);
    struct msghdr *msg = (void *) PT_REGS_PARM2(ctx);
    size_t len = PT_REGS_PARM3(ctx);
    return __usk_sendmsg(ctx, sock, msg, len);
}

SEC("kprobe/unix_stream_sendmsg")
int kprobe__unix_stream_sendmsg(struct pt_regs *ctx)
{
    return __kprobe_unix_sendmsg(ctx);
}

SEC("kprobe/unix_dgram_sendmsg")
int kprobe__unix_dgram_sendmsg(struct pt_regs *ctx)
{
    return __kprobe_unix_sendmsg(ctx);
}

SEC("fentry/unix_stream_sendmsg")
int BPF_PROG(fentry__unix_stream_sendmsg, struct socket *sock, struct msghdr *msg, size_t len)
{
    return __usk_sendmsg((void *) (long) ctx, sock, msg, len);
}

SEC("fentry/unix_dgram_sendmsg")
int BPF_PROG(fentry__unix_dgram_sendmsg, struct socket *sock, struct msghdr *msg, size_t len)
{
    return __usk_sendmsg((void *) (long) ctx, sock, msg, len);
}

char __license[] SEC("license") = "Dual BSD/GPL";

