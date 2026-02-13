// clang-format off
//go:build ignore
// clang-format on
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 转发规则结构体
struct relay_rule
{
    __u32 relay_ip;    // 网络序
    __u32 target_ip;   // 网络序
    __u16 target_port; // 网络序
    unsigned char relay_mac[6];
    unsigned char next_hop_mac[6];
} __attribute__((packed));

// 配置表：Key 是网络序的入站端口 (tcph->dest)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, struct relay_rule);
} config_map SEC(".maps");

// 会话键：利用目标信息和客户端端口锁定唯一连接
struct session_key
{
    __u32 target_ip;   // 网络序
    __u16 target_port; // 网络序
    __u16 client_port; // 网络序
} __attribute__((packed));

struct session_value
{
    __u32 client_ip;
    __u16 relay_port; // 记录是从哪个中继端口进来的，用于回包还原
    unsigned char client_mac[6];
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct session_key);
    __type(value, struct session_value);
} session_map SEC(".maps");

static __always_inline void update_csum(__u16 *csum, __u16 old_val, __u16 new_val)
{
    __u32 sum = *csum;
    sum = ~sum & 0xFFFF;
    sum += ~old_val & 0xFFFF;
    sum += new_val;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    *csum = ~sum & 0xFFFF;
}

SEC("xdp")
int xdp_relay_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcph = (void *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // 1. 查找匹配的转发规则
    __u16 dport = tcph->dest;
    struct relay_rule *rule = bpf_map_lookup_elem(&config_map, &dport);

    if (rule)
    {
        // 网络序准备
        __u32 r_ip_net = rule->relay_ip;
        __u32 t_ip_net = rule->target_ip;
        __u16 t_port_net = rule->target_port;

        // 2. 记录会话 (正向)
        struct session_key skey = {
            .target_ip = t_ip_net,
            .target_port = t_port_net,
            .client_port = tcph->source};
        struct session_value sval = {
            .client_ip = iph->saddr,
            .relay_port = dport // 存入当前中继端口 (网络序)
        };
        __builtin_memcpy(sval.client_mac, eth->h_source, 6);
        bpf_map_update_elem(&session_map, &skey, &sval, BPF_ANY);

        // 3. 执行校验和更新 (DNAT + SNAT)
        update_csum(&tcph->check, (__u16)(iph->daddr & 0xFFFF), (__u16)(t_ip_net & 0xFFFF));
        update_csum(&tcph->check, (__u16)(iph->daddr >> 16), (__u16)(t_ip_net >> 16));
        update_csum(&tcph->check, (__u16)(iph->saddr & 0xFFFF), (__u16)(r_ip_net & 0xFFFF));
        update_csum(&tcph->check, (__u16)(iph->saddr >> 16), (__u16)(r_ip_net >> 16));
        update_csum(&tcph->check, tcph->dest, t_port_net);

        update_csum(&iph->check, (__u16)(iph->daddr & 0xFFFF), (__u16)(t_ip_net & 0xFFFF));
        update_csum(&iph->check, (__u16)(iph->daddr >> 16), (__u16)(t_ip_net >> 16));
        update_csum(&iph->check, (__u16)(iph->saddr & 0xFFFF), (__u16)(r_ip_net & 0xFFFF));
        update_csum(&iph->check, (__u16)(iph->saddr >> 16), (__u16)(r_ip_net >> 16));

        // 4. 修改包字段
        iph->daddr = t_ip_net;
        iph->saddr = r_ip_net;
        tcph->dest = t_port_net;
        __builtin_memcpy(eth->h_dest, rule->next_hop_mac, 6);
        __builtin_memcpy(eth->h_source, rule->relay_mac, 6);

        return XDP_TX;
    }

    // --- 反向：Target -> Relay -> Client ---
    struct session_key rskey = {
        .target_ip = iph->saddr,
        .target_port = tcph->source,
        .client_port = tcph->dest};
    struct session_value *rsval = bpf_map_lookup_elem(&session_map, &rskey);

    if (rsval)
    {
        __u32 r_ip_net = iph->daddr; // 中继 IP 就是当前目的 IP

        update_csum(&tcph->check, (__u16)(iph->saddr & 0xFFFF), (__u16)(r_ip_net & 0xFFFF));
        update_csum(&tcph->check, (__u16)(iph->saddr >> 16), (__u16)(r_ip_net >> 16));
        update_csum(&tcph->check, (__u16)(iph->daddr & 0xFFFF), (__u16)(rsval->client_ip & 0xFFFF));
        update_csum(&tcph->check, (__u16)(iph->daddr >> 16), (__u16)(rsval->client_ip >> 16));
        update_csum(&tcph->check, tcph->source, rsval->relay_port);

        update_csum(&iph->check, (__u16)(iph->saddr & 0xFFFF), (__u16)(r_ip_net & 0xFFFF));
        update_csum(&iph->check, (__u16)(iph->saddr >> 16), (__u16)(r_ip_net >> 16));
        update_csum(&iph->check, (__u16)(iph->daddr & 0xFFFF), (__u16)(rsval->client_ip & 0xFFFF));
        update_csum(&iph->check, (__u16)(iph->daddr >> 16), (__u16)(rsval->client_ip >> 16));

        iph->saddr = r_ip_net;
        iph->daddr = rsval->client_ip;
        tcph->source = rsval->relay_port;
        __builtin_memcpy(eth->h_dest, rsval->client_mac, 6);
        // 原路返回，源 MAC 是本机
        return XDP_TX;
    }

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";