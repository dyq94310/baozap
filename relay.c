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

struct relay_config
{
    __u32 relay_ip;    // 主机字节序
    __u32 target_ip;   // 主机字节序
    __u16 relay_port;  // 主机字节序
    __u16 target_port; // 主机字节序
    unsigned char relay_mac[6];
    unsigned char next_hop_mac[6];
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct relay_config);
} config_map SEC(".maps");

// 并发改进：使用客户端端口作为 Key
struct session_value
{
    __u32 client_ip;
    unsigned char client_mac[6];
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535); // 支持更多并发连接
    __type(key, __u16);         // Key 是客户端的源端口
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

    __u32 zero = 0;
    struct relay_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return XDP_PASS;

    // 转换网络序
    __u32 r_ip_net = bpf_htonl(cfg->relay_ip);
    __u32 t_ip_net = bpf_htonl(cfg->target_ip);
    __u16 r_port_net = bpf_htons(cfg->relay_port);
    __u16 t_port_net = bpf_htons(cfg->target_port);

    // --- 正向：Client -> Relay -> Target ---
    if (tcph->dest == r_port_net)
    {
        // 存储会话：以客户端源端口为 Key
        __u16 c_port = tcph->source;
        struct session_value sval = {.client_ip = iph->saddr};
        __builtin_memcpy(sval.client_mac, eth->h_source, 6);
        bpf_map_update_elem(&session_map, &c_port, &sval, BPF_ANY);

        // 更新 TCP 校验和 (包含伪首部和端口)
        update_csum(&tcph->check, (__u16)(iph->daddr & 0xFFFF), (__u16)(t_ip_net & 0xFFFF));
        update_csum(&tcph->check, (__u16)(iph->daddr >> 16), (__u16)(t_ip_net >> 16));
        update_csum(&tcph->check, (__u16)(iph->saddr & 0xFFFF), (__u16)(r_ip_net & 0xFFFF));
        update_csum(&tcph->check, (__u16)(iph->saddr >> 16), (__u16)(r_ip_net >> 16));
        update_csum(&tcph->check, tcph->dest, t_port_net);

        // 更新 IP 校验和
        update_csum(&iph->check, (__u16)(iph->daddr & 0xFFFF), (__u16)(t_ip_net & 0xFFFF));
        update_csum(&iph->check, (__u16)(iph->daddr >> 16), (__u16)(t_ip_net >> 16));
        update_csum(&iph->check, (__u16)(iph->saddr & 0xFFFF), (__u16)(r_ip_net & 0xFFFF));
        update_csum(&iph->check, (__u16)(iph->saddr >> 16), (__u16)(r_ip_net >> 16));

        iph->daddr = t_ip_net;
        iph->saddr = r_ip_net;
        tcph->dest = t_port_net;
        __builtin_memcpy(eth->h_dest, cfg->next_hop_mac, 6);
        __builtin_memcpy(eth->h_source, cfg->relay_mac, 6);

        return XDP_TX;
    }

    // --- 反向：Target -> Relay -> Client ---
    if (iph->saddr == t_ip_net && tcph->source == t_port_net)
    {
        __u16 c_port = tcph->dest; // 回包的目的端口就是原客户端的源端口
        struct session_value *sval = bpf_map_lookup_elem(&session_map, &c_port);
        if (sval)
        {
            // 【核心修复】反向 TCP 校验和更新
            update_csum(&tcph->check, (__u16)(iph->saddr & 0xFFFF), (__u16)(r_ip_net & 0xFFFF));
            update_csum(&tcph->check, (__u16)(iph->saddr >> 16), (__u16)(r_ip_net >> 16));
            update_csum(&tcph->check, (__u16)(iph->daddr & 0xFFFF), (__u16)(sval->client_ip & 0xFFFF));
            update_csum(&tcph->check, (__u16)(iph->daddr >> 16), (__u16)(sval->client_ip >> 16));
            update_csum(&tcph->check, tcph->source, r_port_net);

            // 反向 IP 校验和更新
            update_csum(&iph->check, (__u16)(iph->saddr & 0xFFFF), (__u16)(r_ip_net & 0xFFFF));
            update_csum(&iph->check, (__u16)(iph->saddr >> 16), (__u16)(r_ip_net >> 16));
            update_csum(&iph->check, (__u16)(iph->daddr & 0xFFFF), (__u16)(sval->client_ip & 0xFFFF));
            update_csum(&iph->check, (__u16)(iph->daddr >> 16), (__u16)(sval->client_ip >> 16));

            iph->saddr = r_ip_net;
            iph->daddr = sval->client_ip;
            tcph->source = r_port_net;
            __builtin_memcpy(eth->h_dest, sval->client_mac, 6);
            __builtin_memcpy(eth->h_source, cfg->relay_mac, 6);

            return XDP_TX;
        }
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";