// clang-format off
//go:build ignore
// clang-format on

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SNAT_PORT_BASE 49152u
#define SNAT_PORT_MASK 0x3FFFu // 16384 ports: 49152..65535
#define SNAT_TRIES 16          // fixed unroll tries

/* IP flags. */
#define IP_CE 0x8000     /* Flag: "Congestion"		*/
#define IP_DF 0x4000     /* Flag: "Don't Fragment"	*/
#define IP_MF 0x2000     /* Flag: "More Fragments"	*/
#define IP_OFFSET 0x1FFF /* "Fragment Offset" part	*/

volatile const __u32 debug_enabled SEC(".data");

enum stat_key
{
    STAT_FORWARD_HIT = 0,
    STAT_REVERSE_HIT = 1,
    STAT_REDIRECT = 2,
    STAT_PASS = 3,
    STAT_DROP = 4,
    STAT_MAX = 5,
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// 定义一个宏，方便调用
#define DEBUG_PRINTK(fmt, ...)              \
    do                                      \
    {                                       \
        if (debug_enabled)                  \
            bpf_printk(fmt, ##__VA_ARGS__); \
    } while (0)

static __always_inline void inc_stat(__u32 k)
{
    // Keep the forwarding hot path minimal unless debug is explicitly enabled.
    if (!debug_enabled)
        return;

    __u64 *v = bpf_map_lookup_elem(&stats_map, &k);
    if (v)
        (*v)++;
}

#define RETURN_PASS()        \
    do                       \
    {                        \
        inc_stat(STAT_PASS); \
        return XDP_PASS;     \
    } while (0)

struct relay_rule
{
    __u32 relay_ip;    // raw (little-endian u32 from packet field)
    __u32 target_ip;   // raw
    __u16 target_port; // network order (raw like tcp/udp header field)
    unsigned char relay_mac[6];
    unsigned char next_hop_mac[6];
    __u32 relay_ifindex; // ingress ifindex for client->relay traffic
    __u32 tx_ifindex; // egress ifindex for forward path (0 => XDP_TX)
} __attribute__((packed));

// Key: relay service port (network order raw)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, struct relay_rule);
} config_map SEC(".maps");

// forward key: (vip, service_port, client_ip, client_port, proto)
struct fwd_key
{
    __u32 vip;          // iph->daddr (raw)
    __u32 client_ip;    // iph->saddr (raw)
    __u16 service_port; // original dport (raw)
    __u16 client_port;  // original sport (raw)
    __u8 proto;         // TCP/UDP
    __u8 pad1;
    __u16 pad2;
};

// forward value: resolved target + chosen snat_port + L2 data
struct fwd_val
{
    __u32 snat_ip;     // relay_ip (raw)
    __u32 target_ip;   // raw
    __u16 target_port; // raw
    __u16 snat_port;   // raw (allocated)
    unsigned char relay_mac[6];
    unsigned char next_hop_mac[6];
    __u32 tx_ifindex; // 0 => XDP_TX, otherwise redirect to this ifindex
};

// reverse key: (snat_ip, target_ip, target_port, snat_port, proto)
struct rev_key
{
    __u32 snat_ip;     // iph->daddr on return path (raw)
    __u32 target_ip;   // iph->saddr on return path (raw)
    __u16 target_port; // sport on return path (raw)
    __u16 snat_port;   // dport on return path (raw)
    __u8 proto;
    __u8 pad1;
    __u16 pad2;
};

// reverse value: who is the client + what service_port to show to client
struct rev_val
{
    __u32 client_ip;    // raw
    __u16 client_port;  // raw
    __u16 service_port; // raw (client sees src port as this)
    __u32 vip;          // original destination ip from client packet
    unsigned char client_mac[6];
    unsigned char relay_mac[6]; // relay MAC observed by client on ingress
    __u32 client_ifindex;       // ingress ifindex for return redirect
};

// LRU: UDP 没有 close，必须 LRU
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, struct fwd_key);
    __type(value, struct fwd_val);
} fwd_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, struct rev_key);
    __type(value, struct rev_val);
} rev_map SEC(".maps");

// RFC1624 incremental checksum update
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

// UDP/IPv4: checksum=0 means "no checksum" => skip update.
// If old != 0 and updated becomes 0, must set to 0xFFFF.
static __always_inline void l4_csum_replace16(__u8 proto, __u16 *csum, __u16 old_val, __u16 new_val)
{
    if (proto == IPPROTO_UDP && *csum == 0)
        return;
    update_csum(csum, old_val, new_val);
}

static __always_inline void udp_csum_fixup_zero(__u8 proto, __u16 *csum, __u16 old_csum)
{
    if (proto == IPPROTO_UDP && old_csum != 0 && *csum == 0)
        *csum = 0xFFFF;
}

static __always_inline int parse_l4(void *l4, void *data_end, __u8 proto,
                                    __u16 **sportp, __u16 **dportp, __u16 **checkp,
                                    struct tcphdr **tcph_out)
{
    if (proto == IPPROTO_TCP)
    {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *sportp = &tcp->source;
        *dportp = &tcp->dest;
        *checkp = &tcp->check;
        if (tcph_out)
            *tcph_out = tcp;
        return 0;
    }
    if (proto == IPPROTO_UDP)
    {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return -1;
        *sportp = &udp->source;
        *dportp = &udp->dest;
        *checkp = &udp->check;
        if (tcph_out)
            *tcph_out = 0;
        return 0;
    }
    return -1;
}

static __always_inline __u16 alloc_snat_port(__u32 seed, struct rev_key *rkey, struct rev_val *rval)
{
#pragma unroll
    for (int i = 0; i < SNAT_TRIES; i++)
    {
        __u16 host_p = (__u16)(SNAT_PORT_BASE + ((seed + (__u32)i) & SNAT_PORT_MASK));
        __u16 cand = bpf_htons(host_p); // store/write in raw network order

        rkey->snat_port = cand;

        // Try reserve this port by inserting reverse mapping
        if (bpf_map_update_elem(&rev_map, rkey, rval, BPF_NOEXIST) == 0)
        {
            return cand; // success
        }
    }
    return 0;
}

SEC("xdp")
int xdp_relay_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        RETURN_PASS();

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        RETURN_PASS();

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        RETURN_PASS();

    if (iph->version != 4)
        RETURN_PASS();

    // 1. 日志：捕获到 IP 包
    __u8 proto = iph->protocol;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
    {
        if (proto == IPPROTO_UDP)
        {
            DEBUG_PRINTK("DEBUG: recv %s pkt: src %pI4 -> dst %pI4",
                         proto == IPPROTO_TCP ? "TCP" : "UDP", &iph->saddr, &iph->daddr);
        }
    }
    else
    {
        RETURN_PASS();
    }

    // drop fragments (no完整L4)
    if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
    {
        DEBUG_PRINTK("DEBUG: Dropping fragmented packet from %pI4", &iph->saddr);
        RETURN_PASS();
    }

    // support IP options
    __u32 ihl_bytes = (__u32)iph->ihl * 4;
    if (ihl_bytes < sizeof(*iph))
        RETURN_PASS();

    void *l4 = (void *)((char *)iph + ihl_bytes);
    if ((void *)((char *)l4 + sizeof(struct udphdr)) > data_end)
        RETURN_PASS();

    __u16 *sportp = 0, *dportp = 0, *checkp = 0;
    struct tcphdr *tcph = 0;
    if (parse_l4(l4, data_end, proto, &sportp, &dportp, &checkp, &tcph) < 0)
        RETURN_PASS();

    __u16 sport = *sportp;
    __u16 dport = *dportp;

    // 2. 定位：收到原始包的日志
    if (proto == IPPROTO_UDP)
    {
        DEBUG_PRINTK("IN_UDP: %pI4:%d -> %pI4:%d (csum: 0x%x)",
                     &iph->saddr, bpf_ntohs(sport), &iph->daddr, bpf_ntohs(dport), bpf_ntohs(*checkp));
    }
    else
    {
        DEBUG_PRINTK("IN_TCP: %pI4:%d -> %pI4:%d",
                     &iph->saddr, bpf_ntohs(sport), &iph->daddr, bpf_ntohs(dport));
    }

    // ---------- 1) reverse first: Target -> Relay(snat_port) -> Client ----------
    // return packet: src=target_ip:target_port, dst=snat_ip:snat_port
    struct rev_key rkey = {
        .snat_ip = iph->daddr,
        .target_ip = iph->saddr,
        .target_port = sport,
        .snat_port = dport,
        .proto = proto,
    };

    struct rev_val *rval = bpf_map_lookup_elem(&rev_map, &rkey);
    if (rval)
    {
        inc_stat(STAT_REVERSE_HIT);
        DEBUG_PRINTK("DEBUG: Found Rev Map! NAT to Client %pI4:%d", &rval->client_ip, bpf_ntohs(rval->client_port));
        __u32 old_saddr = iph->saddr; // target
        __u32 old_daddr = iph->daddr; // snat_ip
        __u32 new_saddr = rval->vip;  // restore original vip seen by client
        __u32 new_daddr = rval->client_ip;

        __u16 old_sport = sport;
        __u16 old_dport = dport;
        __u16 new_sport = rval->service_port;
        __u16 new_dport = rval->client_port;

        __u16 old_l4_csum = *checkp;

        // L4 checksum updates: pseudo header + ports
        l4_csum_replace16(proto, checkp, (__u16)(old_saddr & 0xFFFF), (__u16)(new_saddr & 0xFFFF));
        l4_csum_replace16(proto, checkp, (__u16)(old_saddr >> 16), (__u16)(new_saddr >> 16));
        l4_csum_replace16(proto, checkp, (__u16)(old_daddr & 0xFFFF), (__u16)(new_daddr & 0xFFFF));
        l4_csum_replace16(proto, checkp, (__u16)(old_daddr >> 16), (__u16)(new_daddr >> 16));

        l4_csum_replace16(proto, checkp, old_sport, new_sport);
        l4_csum_replace16(proto, checkp, old_dport, new_dport);
        udp_csum_fixup_zero(proto, checkp, old_l4_csum);

        // IP header checksum updates (saddr/daddr)
        update_csum(&iph->check, (__u16)(old_saddr & 0xFFFF), (__u16)(new_saddr & 0xFFFF));
        update_csum(&iph->check, (__u16)(old_saddr >> 16), (__u16)(new_saddr >> 16));
        update_csum(&iph->check, (__u16)(old_daddr & 0xFFFF), (__u16)(new_daddr & 0xFFFF));
        update_csum(&iph->check, (__u16)(old_daddr >> 16), (__u16)(new_daddr >> 16));

        // write back
        iph->saddr = new_saddr;
        iph->daddr = new_daddr;
        *sportp = new_sport;
        *dportp = new_dport;

        // L2 rewrite: dst=client_mac, src=relay_mac captured on client ingress
        __builtin_memcpy(eth->h_dest, rval->client_mac, 6);
        __builtin_memcpy(eth->h_source, rval->relay_mac, 6);

        if (rval->client_ifindex != 0 && rval->client_ifindex != ctx->ingress_ifindex)
        {
            inc_stat(STAT_REDIRECT);
            return bpf_redirect(rval->client_ifindex, 0);
        }
        return XDP_TX;
    }

    // ---------- 2) forward: Client -> Relay(service_port) -> Target ----------
    // Try reuse existing mapping first (no config lookup on hit)
    struct fwd_key fkey = {
        .vip = iph->daddr,
        .client_ip = iph->saddr,
        .service_port = dport,
        .client_port = sport,
        .proto = proto,
    };

    struct fwd_val *fval = bpf_map_lookup_elem(&fwd_map, &fkey);
    struct fwd_val new_fval;

    if (!fval)
    {
        // Miss: need rule to create mapping
        struct relay_rule *rule = bpf_map_lookup_elem(&config_map, &dport);
        if (!rule)
        {
            // 打印 dport 的原始数值和转换后的数值
            DEBUG_PRINTK("DEBUG: Port Lookup Failed. Raw(Network): %d, Host: %d",
                         dport, bpf_ntohs(dport));
            RETURN_PASS();
        }
        if (rule->relay_ifindex != 0 && rule->relay_ifindex != ctx->ingress_ifindex)
            RETURN_PASS();

        DEBUG_PRINTK("MATCH: Config rule found, creating new session");
        // Build reverse reservation template
        struct rev_key new_rkey = {
            .snat_ip = rule->relay_ip,
            .target_ip = rule->target_ip,
            .target_port = rule->target_port,
            .snat_port = 0, // to be allocated
            .proto = proto,
        };

        struct rev_val new_rval = {
            .client_ip = iph->saddr,
            .client_port = sport,
            .service_port = dport,
            .vip = iph->daddr,
            .client_ifindex = ctx->ingress_ifindex,
        };
        __builtin_memcpy(new_rval.client_mac, eth->h_source, 6);
        __builtin_memcpy(new_rval.relay_mac, eth->h_dest, 6);

        // Allocate + reserve snat_port via rev_map insert
        __u16 snat_port = alloc_snat_port(bpf_get_prandom_u32(), &new_rkey, &new_rval);
        if (snat_port == 0)
            RETURN_PASS(); // no port available (or too many collisions)

        // Build fwd_val (store resolved info + L2 data) so fast path doesn't touch config_map
        new_fval.snat_ip = rule->relay_ip;
        new_fval.target_ip = rule->target_ip;
        new_fval.target_port = rule->target_port;
        new_fval.snat_port = snat_port;
        __builtin_memcpy(new_fval.relay_mac, rule->relay_mac, 6);
        __builtin_memcpy(new_fval.next_hop_mac, rule->next_hop_mac, 6);
        new_fval.tx_ifindex = rule->tx_ifindex;

        // Insert fwd_map; if lose race, cleanup rev reservation and use existing mapping
        if (bpf_map_update_elem(&fwd_map, &fkey, &new_fval, BPF_NOEXIST) != 0)
        {
            // someone else created mapping for this flow, remove our reserved reverse key
            bpf_map_delete_elem(&rev_map, &new_rkey);

            fval = bpf_map_lookup_elem(&fwd_map, &fkey);
            if (!fval)
                RETURN_PASS(); // extremely rare
        }
        else
        {
            fval = &new_fval;
        }
    }
    else
    {
        DEBUG_PRINTK("DEBUG: Found existing Fwd Map entry");
    }

    // Now apply forward NAT using fval
    {
        inc_stat(STAT_FORWARD_HIT);
        __u32 old_saddr = iph->saddr;    // client
        __u32 old_daddr = iph->daddr;    // vip
        __u32 new_saddr = fval->snat_ip; // relay ip
        __u32 new_daddr = fval->target_ip;

        __u16 old_sport = sport;
        __u16 old_dport = dport;
        __u16 new_sport = fval->snat_port;
        __u16 new_dport = fval->target_port;

        __u16 old_l4_csum = *checkp;

        // L4 checksum updates: pseudo header + ports
        l4_csum_replace16(proto, checkp, (__u16)(old_saddr & 0xFFFF), (__u16)(new_saddr & 0xFFFF));
        l4_csum_replace16(proto, checkp, (__u16)(old_saddr >> 16), (__u16)(new_saddr >> 16));
        l4_csum_replace16(proto, checkp, (__u16)(old_daddr & 0xFFFF), (__u16)(new_daddr & 0xFFFF));
        l4_csum_replace16(proto, checkp, (__u16)(old_daddr >> 16), (__u16)(new_daddr >> 16));

        l4_csum_replace16(proto, checkp, old_sport, new_sport);
        l4_csum_replace16(proto, checkp, old_dport, new_dport);
        udp_csum_fixup_zero(proto, checkp, old_l4_csum);

        // IP header checksum updates
        update_csum(&iph->check, (__u16)(old_saddr & 0xFFFF), (__u16)(new_saddr & 0xFFFF));
        update_csum(&iph->check, (__u16)(old_saddr >> 16), (__u16)(new_saddr >> 16));
        update_csum(&iph->check, (__u16)(old_daddr & 0xFFFF), (__u16)(new_daddr & 0xFFFF));
        update_csum(&iph->check, (__u16)(old_daddr >> 16), (__u16)(new_daddr >> 16));

        // write back
        iph->saddr = new_saddr;
        iph->daddr = new_daddr;
        *sportp = new_sport;
        *dportp = new_dport;

        // L2 rewrite
        __builtin_memcpy(eth->h_dest, fval->next_hop_mac, 6);
        __builtin_memcpy(eth->h_source, fval->relay_mac, 6);

        if (fval->tx_ifindex != 0 && fval->tx_ifindex != ctx->ingress_ifindex)
        {
            inc_stat(STAT_REDIRECT);
            return bpf_redirect(fval->tx_ifindex, 0);
        }
        return XDP_TX;
    }
}

// TC clsact 版本：在 __sk_buff 上复用相同的 NAT 转发逻辑。
#define TC_INC_STAT(k) \
    do                 \
    {                  \
    } while (0)

#define RETURN_TC_OK()       \
    do                       \
    {                        \
        TC_INC_STAT(STAT_PASS); \
        return TC_ACT_OK;    \
    } while (0)

static __always_inline int tc_redirect_tx(__u32 ifindex)
{
    return bpf_redirect(ifindex, 0);
}

SEC("tc")
int tc_relay_func(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        RETURN_TC_OK();

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        RETURN_TC_OK();

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        RETURN_TC_OK();

    if (iph->version != 4)
        RETURN_TC_OK();

    __u8 proto = iph->protocol;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        RETURN_TC_OK();

    if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
        RETURN_TC_OK();

    __u32 ihl_bytes = (__u32)iph->ihl * 4;
    if (ihl_bytes < sizeof(*iph))
        RETURN_TC_OK();

    void *l4 = (void *)((char *)iph + ihl_bytes);
    if ((void *)((char *)l4 + sizeof(struct udphdr)) > data_end)
        RETURN_TC_OK();

    __u16 *sportp = 0, *dportp = 0, *checkp = 0;
    struct tcphdr *tcph = 0;
    if (parse_l4(l4, data_end, proto, &sportp, &dportp, &checkp, &tcph) < 0)
        RETURN_TC_OK();

    __u16 sport = *sportp;
    __u16 dport = *dportp;

    struct rev_key rkey = {
        .snat_ip = iph->daddr,
        .target_ip = iph->saddr,
        .target_port = sport,
        .snat_port = dport,
        .proto = proto,
    };

    struct rev_val *rval = bpf_map_lookup_elem(&rev_map, &rkey);
    if (rval)
    {
        TC_INC_STAT(STAT_REVERSE_HIT);

        __u32 old_saddr = iph->saddr;
        __u32 old_daddr = iph->daddr;
        __u32 new_saddr = rval->vip;
        __u32 new_daddr = rval->client_ip;

        __u16 old_sport = sport;
        __u16 old_dport = dport;
        __u16 new_sport = rval->service_port;
        __u16 new_dport = rval->client_port;

        __u16 old_l4_csum = *checkp;

        l4_csum_replace16(proto, checkp, (__u16)(old_saddr & 0xFFFF), (__u16)(new_saddr & 0xFFFF));
        l4_csum_replace16(proto, checkp, (__u16)(old_saddr >> 16), (__u16)(new_saddr >> 16));
        l4_csum_replace16(proto, checkp, (__u16)(old_daddr & 0xFFFF), (__u16)(new_daddr & 0xFFFF));
        l4_csum_replace16(proto, checkp, (__u16)(old_daddr >> 16), (__u16)(new_daddr >> 16));

        l4_csum_replace16(proto, checkp, old_sport, new_sport);
        l4_csum_replace16(proto, checkp, old_dport, new_dport);
        udp_csum_fixup_zero(proto, checkp, old_l4_csum);

        update_csum(&iph->check, (__u16)(old_saddr & 0xFFFF), (__u16)(new_saddr & 0xFFFF));
        update_csum(&iph->check, (__u16)(old_saddr >> 16), (__u16)(new_saddr >> 16));
        update_csum(&iph->check, (__u16)(old_daddr & 0xFFFF), (__u16)(new_daddr & 0xFFFF));
        update_csum(&iph->check, (__u16)(old_daddr >> 16), (__u16)(new_daddr >> 16));

        iph->saddr = new_saddr;
        iph->daddr = new_daddr;
        *sportp = new_sport;
        *dportp = new_dport;

        __builtin_memcpy(eth->h_dest, rval->client_mac, 6);
        __builtin_memcpy(eth->h_source, rval->relay_mac, 6);

        __u32 tx_ifindex = rval->client_ifindex ? rval->client_ifindex : skb->ifindex;
        if (tx_ifindex != skb->ifindex)
            TC_INC_STAT(STAT_REDIRECT);
        return tc_redirect_tx(tx_ifindex);
    }

    struct fwd_key fkey = {
        .vip = iph->daddr,
        .client_ip = iph->saddr,
        .service_port = dport,
        .client_port = sport,
        .proto = proto,
    };

    struct fwd_val *fval = bpf_map_lookup_elem(&fwd_map, &fkey);
    struct fwd_val new_fval;

    if (!fval)
    {
        struct relay_rule *rule = bpf_map_lookup_elem(&config_map, &dport);
        if (!rule)
            RETURN_TC_OK();

        if (rule->relay_ifindex != 0 && rule->relay_ifindex != skb->ifindex)
            RETURN_TC_OK();

        struct rev_key new_rkey = {
            .snat_ip = rule->relay_ip,
            .target_ip = rule->target_ip,
            .target_port = rule->target_port,
            .snat_port = 0,
            .proto = proto,
        };

        struct rev_val new_rval = {
            .client_ip = iph->saddr,
            .client_port = sport,
            .service_port = dport,
            .vip = iph->daddr,
            .client_ifindex = skb->ifindex,
        };
        __builtin_memcpy(new_rval.client_mac, eth->h_source, 6);
        __builtin_memcpy(new_rval.relay_mac, eth->h_dest, 6);

        __u16 snat_port = alloc_snat_port(bpf_get_prandom_u32(), &new_rkey, &new_rval);
        if (snat_port == 0)
            RETURN_TC_OK();

        new_fval.snat_ip = rule->relay_ip;
        new_fval.target_ip = rule->target_ip;
        new_fval.target_port = rule->target_port;
        new_fval.snat_port = snat_port;
        __builtin_memcpy(new_fval.relay_mac, rule->relay_mac, 6);
        __builtin_memcpy(new_fval.next_hop_mac, rule->next_hop_mac, 6);
        new_fval.tx_ifindex = rule->tx_ifindex;

        if (bpf_map_update_elem(&fwd_map, &fkey, &new_fval, BPF_NOEXIST) != 0)
        {
            bpf_map_delete_elem(&rev_map, &new_rkey);

            // Concurrent packet may have created fwd entry first.
            // Reuse it instead of letting this packet fall back to kernel path.
            fval = bpf_map_lookup_elem(&fwd_map, &fkey);
            if (!fval)
                RETURN_TC_OK();
        }
        else
        {
            fval = &new_fval;
        }
    }

    TC_INC_STAT(STAT_FORWARD_HIT);

    __u32 old_saddr = iph->saddr;
    __u32 old_daddr = iph->daddr;
    __u32 new_saddr = fval->snat_ip;
    __u32 new_daddr = fval->target_ip;

    __u16 old_sport = sport;
    __u16 old_dport = dport;
    __u16 new_sport = fval->snat_port;
    __u16 new_dport = fval->target_port;

    __u16 old_l4_csum = *checkp;

    l4_csum_replace16(proto, checkp, (__u16)(old_saddr & 0xFFFF), (__u16)(new_saddr & 0xFFFF));
    l4_csum_replace16(proto, checkp, (__u16)(old_saddr >> 16), (__u16)(new_saddr >> 16));
    l4_csum_replace16(proto, checkp, (__u16)(old_daddr & 0xFFFF), (__u16)(new_daddr & 0xFFFF));
    l4_csum_replace16(proto, checkp, (__u16)(old_daddr >> 16), (__u16)(new_daddr >> 16));

    l4_csum_replace16(proto, checkp, old_sport, new_sport);
    l4_csum_replace16(proto, checkp, old_dport, new_dport);
    udp_csum_fixup_zero(proto, checkp, old_l4_csum);

    update_csum(&iph->check, (__u16)(old_saddr & 0xFFFF), (__u16)(new_saddr & 0xFFFF));
    update_csum(&iph->check, (__u16)(old_saddr >> 16), (__u16)(new_saddr >> 16));
    update_csum(&iph->check, (__u16)(old_daddr & 0xFFFF), (__u16)(new_daddr & 0xFFFF));
    update_csum(&iph->check, (__u16)(old_daddr >> 16), (__u16)(new_daddr >> 16));

    iph->saddr = new_saddr;
    iph->daddr = new_daddr;
    *sportp = new_sport;
    *dportp = new_dport;

    __builtin_memcpy(eth->h_dest, fval->next_hop_mac, 6);
    __builtin_memcpy(eth->h_source, fval->relay_mac, 6);

    __u32 tx_ifindex = fval->tx_ifindex ? fval->tx_ifindex : skb->ifindex;
    if (tx_ifindex != skb->ifindex)
        TC_INC_STAT(STAT_REDIRECT);
    return tc_redirect_tx(tx_ifindex);
}

char _license[] SEC("license") = "GPL";
