// clang-format off
//go:build ignore
// clang-format on

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/if_packet.h>
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
#define IPV4_MAX_IHL_BYTES 60u
#define TC_PULL_LEN (sizeof(struct ethhdr) + IPV4_MAX_IHL_BYTES + sizeof(struct tcphdr))

#define RETURN_PASS()        \
    do                       \
    {                        \
        return XDP_PASS;     \
    } while (0)

struct relay_rule {
	__u32 relay_ip;    // raw (little-endian u32 from packet field)
	__u32 target_ip;   // raw
	__u16 target_port; // network order (raw like tcp/udp header field)
	__u8 relay_mac[6];
	__u8 next_hop_mac[6];
	__u16 pad;           // alignment padding to match Go's structs.HostLayout
	__u32 relay_ifindex; // ingress ifindex for client->relay traffic
	__u32 tx_ifindex;    // egress ifindex for forward path (0 => XDP_TX)
};

// Key: relay service port (network order raw)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u16);
	__type(value, struct relay_rule);
} config_map SEC(".maps");

// forward key: (vip, service_port, client_ip, client_port, proto)
struct fwd_key {
	__u32 vip;	    // iph->daddr (raw)
	__u32 client_ip;    // iph->saddr (raw)
	__u16 service_port; // original dport (raw)
	__u16 client_port;  // original sport (raw)
	__u8 proto;	    // TCP/UDP
	__u8 pad1;
	__u16 pad2;
};

// forward value: resolved target + chosen snat_port + L2 data
struct fwd_val {
	__u32 snat_ip;	   // relay_ip (raw)
	__u32 target_ip;   // raw
	__u16 target_port; // raw
	__u16 snat_port;   // raw (allocated)
	__u8 relay_mac[6];
	__u8 next_hop_mac[6];
	__u32 tx_ifindex; // 0 => XDP_TX, otherwise redirect to this ifindex
};

// reverse key: (snat_ip, target_ip, target_port, snat_port, proto)
struct rev_key {
	__u32 snat_ip;	   // iph->daddr on return path (raw)
	__u32 target_ip;   // iph->saddr on return path (raw)
	__u16 target_port; // sport on return path (raw)
	__u16 snat_port;   // dport on return path (raw)
	__u8 proto;
	__u8 pad1;
	__u16 pad2;
};

// reverse value: who is the client + what service_port to show to client
struct rev_val {
	__u32 client_ip;    // raw
	__u16 client_port;  // raw
	__u16 service_port; // raw (client sees src port as this)
	__u32 vip;	    // original destination ip from client packet
	__u8 client_mac[6];
	__u8 relay_mac[6];    // relay MAC observed by client on ingress
	__u32 client_ifindex; // ingress ifindex for return redirect
};

// LRU: UDP 没有 close，必须 LRU
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct fwd_key);
	__type(value, struct fwd_val);
} fwd_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct rev_key);
	__type(value, struct rev_val);
} rev_map SEC(".maps");

enum debug_counter_key {
	DEBUG_TC_NON_IP = 0,
	DEBUG_TC_NON_IPV4 = 1,
	DEBUG_TC_UNSUPPORTED_PROTO = 2,
	DEBUG_TC_FRAGMENT = 3,
	DEBUG_TC_PARSE_FAIL = 4,
	DEBUG_TC_REVERSE_HIT = 5,
	DEBUG_TC_REVERSE_MISS = 6,
	DEBUG_TC_NO_RULE = 7,
	DEBUG_TC_IF_MISMATCH = 8,
	DEBUG_TC_FORWARD_NEW = 9,
	DEBUG_TC_FORWARD_REUSE = 10,
	DEBUG_TC_REDIRECT = 11,
	DEBUG_TC_LAST_NO_RULE_DPORT = 12,
	DEBUG_TC_LAST_NO_RULE_IFINDEX = 13,
	DEBUG_TC_LAST_NO_RULE_DADDR = 14,
	DEBUG_TC_LAST_REVERSE_MISS_DPORT = 15,
	DEBUG_TC_LAST_REVERSE_MISS_IFINDEX = 16,
	DEBUG_TC_LAST_REVERSE_MISS_DADDR = 17,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 32);
	__type(key, __u32);
	__type(value, __u64);
} debug_map SEC(".maps");

static inline __attribute__((always_inline)) void debug_inc(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&debug_map, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static inline __attribute__((always_inline)) void debug_set(__u32 key, __u64 value)
{
    bpf_map_update_elem(&debug_map, &key, &value, BPF_ANY);
}

// RFC1624 incremental checksum update
static inline __attribute__((always_inline)) void update_csum(__u16 *csum, __u16 old_val, __u16 new_val)
{
    __u32 sum = *csum;
    sum = ~sum & 0xFFFF;
    sum += ~old_val & 0xFFFF;
    sum += new_val;
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    *csum = ~sum & 0xFFFF;
}

static inline __attribute__((always_inline)) void update_csum32(__u16 *csum, __u32 old_val, __u32 new_val)
{
    update_csum(csum, (__u16)(old_val & 0xFFFF), (__u16)(new_val & 0xFFFF));
    update_csum(csum, (__u16)(old_val >> 16), (__u16)(new_val >> 16));
}

static inline __attribute__((always_inline)) void l4_csum_fixup_zero(__u8 proto, __u16 *csum, __u16 old_csum)
{
    if (proto == IPPROTO_UDP && old_csum == 0)
        return;
    if (*csum == 0)
        *csum = 0xFFFF;
}

static inline __attribute__((always_inline)) void ip_csum_fixup_zero(__u16 *csum)
{
    if (*csum == 0)
        *csum = 0xFFFF;
}

static inline __attribute__((always_inline)) int parse_l4(void *l4, void *data_end, __u8 proto,
                                                         __u16 **sportp, __u16 **dportp, __u16 **checkp)
{
    if ((void *)((char *)l4 + 4) > data_end)
        return -1;

    struct udphdr *any_l4 = l4;
    *sportp = &any_l4->source;
    *dportp = &any_l4->dest;

    if (proto == IPPROTO_TCP)
    {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *checkp = &tcp->check;
    }
    else
    {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return -1;
        *checkp = &udp->check;
    }
    return 0;
}

static inline __attribute__((always_inline)) __u16 alloc_snat_port(__u32 seed, struct rev_key *rkey, struct rev_val *rval)
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

    __u8 proto = iph->protocol;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        RETURN_PASS();

    if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
        RETURN_PASS();

    __u32 ihl_bytes = (__u32)iph->ihl * 4;
    if (ihl_bytes < sizeof(*iph))
        RETURN_PASS();

    void *l4 = (void *)((char *)iph + ihl_bytes);
    if ((void *)((char *)l4 + sizeof(struct udphdr)) > data_end)
        RETURN_PASS();

    __u16 *sportp = 0, *dportp = 0, *checkp = 0;
    if (parse_l4(l4, data_end, proto, &sportp, &dportp, &checkp) < 0)
        RETURN_PASS();

    __u16 sport = *sportp;
    __u16 dport = *dportp;

    __u16 dport_host = bpf_ntohs(dport);
    if (dport_host >= SNAT_PORT_BASE)
    {
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
            __u32 old_saddr = iph->saddr; // target
            __u32 old_daddr = iph->daddr; // snat_ip
            __u32 new_saddr = rval->vip;  // restore original vip seen by client
            __u32 new_daddr = rval->client_ip;

            __u16 old_sport = sport;
            __u16 old_dport = dport;
            __u16 new_sport = rval->service_port;
            __u16 new_dport = rval->client_port;

            __u16 old_l4_csum = *checkp;

            if (!(proto == IPPROTO_UDP && old_l4_csum == 0))
            {
                update_csum32(checkp, old_saddr, new_saddr);
                update_csum32(checkp, old_daddr, new_daddr);
                update_csum(checkp, old_sport, new_sport);
                update_csum(checkp, old_dport, new_dport);
                l4_csum_fixup_zero(proto, checkp, old_l4_csum);
            }

            update_csum32(&iph->check, old_saddr, new_saddr);
            update_csum32(&iph->check, old_daddr, new_daddr);
            ip_csum_fixup_zero(&iph->check);

            iph->saddr = new_saddr;
            iph->daddr = new_daddr;
            *sportp = new_sport;
            *dportp = new_dport;

            __builtin_memcpy(eth->h_dest, rval->client_mac, 6);
            __builtin_memcpy(eth->h_source, rval->relay_mac, 6);

            if (rval->client_ifindex != 0 && rval->client_ifindex != ctx->ingress_ifindex)
            {
                return bpf_redirect(rval->client_ifindex, 0);
            }
            return XDP_TX;
        }
    }

    struct fwd_key fkey = {
        .vip = iph->daddr,
        .client_ip = iph->saddr,
        .service_port = dport,
        .client_port = sport,
        .proto = proto,
    };

    struct fwd_val *fval = bpf_map_lookup_elem(&fwd_map, &fkey);
    struct fwd_val new_fval = {};

    if (!fval)
    {
        struct relay_rule *rule = bpf_map_lookup_elem(&config_map, &dport);
        if (!rule)
            RETURN_PASS();
        if (rule->relay_ifindex != 0 && rule->relay_ifindex != ctx->ingress_ifindex)
            RETURN_PASS();

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
            .client_ifindex = ctx->ingress_ifindex,
        };
        __builtin_memcpy(new_rval.client_mac, eth->h_source, 6);
        __builtin_memcpy(new_rval.relay_mac, eth->h_dest, 6);

        __u16 snat_port = alloc_snat_port(bpf_get_prandom_u32(), &new_rkey, &new_rval);
        if (snat_port == 0)
            RETURN_PASS();

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
                RETURN_PASS();
        }
        else
        {
            fval = &new_fval;
        }
    }
    {
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
        if (!(proto == IPPROTO_UDP && old_l4_csum == 0))
        {
            update_csum32(checkp, old_saddr, new_saddr);
            update_csum32(checkp, old_daddr, new_daddr);
            update_csum(checkp, old_sport, new_sport);
            update_csum(checkp, old_dport, new_dport);
            l4_csum_fixup_zero(proto, checkp, old_l4_csum);
        }

        // IP header checksum updates
        update_csum32(&iph->check, old_saddr, new_saddr);
        update_csum32(&iph->check, old_daddr, new_daddr);
        ip_csum_fixup_zero(&iph->check);

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
            return bpf_redirect(fval->tx_ifindex, 0);
        }
        return XDP_TX;
    }
}

// TC clsact 版本：在 __sk_buff 上复用相同的 NAT 转发逻辑。
#define RETURN_TC_OK()       \
    do                       \
    {                        \
        return TC_ACT_OK;    \
    } while (0)

static inline __attribute__((always_inline)) int tc_redirect_tx(__u32 ifindex)
{
    return bpf_redirect(ifindex, 0);
}

static inline __attribute__((always_inline)) int tc_prepare_skb(struct __sk_buff *skb)
{
    /*
     * GRO/GSO traffic often arrives with payload stored in skb frags.
     * We only need L2/L3/L4 headers for NAT, so avoid full linearization
     * of large skbs and keep payload in frags.
     */
    if (bpf_skb_pull_data(skb, TC_PULL_LEN) < 0)
        return -1;
    return 0;
}

static inline __attribute__((always_inline)) int tc_store_bytes(struct __sk_buff *skb, __u32 off, const void *from, __u32 len)
{
    return bpf_skb_store_bytes(skb, off, from, len, BPF_F_INVALIDATE_HASH);
}

static inline __attribute__((always_inline)) int tc_store_ports(struct __sk_buff *skb, __u32 sport_off, __u16 new_sport,
                                                                __u32 dport_off, __u16 new_dport)
{
    if (tc_store_bytes(skb, sport_off, &new_sport, sizeof(new_sport)) < 0)
        return -1;
    if (tc_store_bytes(skb, dport_off, &new_dport, sizeof(new_dport)) < 0)
        return -1;
    return 0;
}

static inline __attribute__((always_inline)) int tc_update_ip_csum(struct __sk_buff *skb, __u32 ip_check_off,
                                                                   __u32 old_saddr, __u32 new_saddr,
                                                                   __u32 old_daddr, __u32 new_daddr)
{
    if (bpf_l3_csum_replace(skb, ip_check_off, old_saddr, new_saddr, sizeof(new_saddr)) < 0)
        return -1;
    if (bpf_l3_csum_replace(skb, ip_check_off, old_daddr, new_daddr, sizeof(new_daddr)) < 0)
        return -1;
    return 0;
}

static inline __attribute__((always_inline)) int tc_update_l4_csum(struct __sk_buff *skb, __u8 proto, __u32 l4_check_off,
                                                                   __u16 old_l4_csum, __u32 old_saddr, __u32 new_saddr,
                                                                   __u32 old_daddr, __u32 new_daddr, __u16 old_sport,
                                                                   __u16 new_sport, __u16 old_dport, __u16 new_dport)
{
    if (proto == IPPROTO_UDP && old_l4_csum == 0)
        return 0;

    if (bpf_l4_csum_replace(skb, l4_check_off, old_saddr, new_saddr, BPF_F_PSEUDO_HDR | sizeof(new_saddr)) < 0)
        return -1;
    if (bpf_l4_csum_replace(skb, l4_check_off, old_daddr, new_daddr, BPF_F_PSEUDO_HDR | sizeof(new_daddr)) < 0)
        return -1;
    if (bpf_l4_csum_replace(skb, l4_check_off, old_sport, new_sport, sizeof(new_sport)) < 0)
        return -1;
    if (bpf_l4_csum_replace(skb, l4_check_off, old_dport, new_dport, sizeof(new_dport)) < 0)
        return -1;
    return 0;
}

SEC("classifier")
int tc_relay_func(struct __sk_buff *skb)
{
    if (tc_prepare_skb(skb) < 0)
        RETURN_TC_OK();

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        RETURN_TC_OK();

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        debug_inc(DEBUG_TC_NON_IP);
        RETURN_TC_OK();
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        RETURN_TC_OK();

    if (iph->version != 4)
    {
        debug_inc(DEBUG_TC_NON_IPV4);
        RETURN_TC_OK();
    }

    __u8 proto = iph->protocol;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
    {
        debug_inc(DEBUG_TC_UNSUPPORTED_PROTO);
        RETURN_TC_OK();
    }

    if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
    {
        debug_inc(DEBUG_TC_FRAGMENT);
        RETURN_TC_OK();
    }

    __u32 ihl_bytes = (__u32)iph->ihl * 4;
    if (ihl_bytes < sizeof(*iph))
        RETURN_TC_OK();

    void *l4 = (void *)((char *)iph + ihl_bytes);
    if ((void *)((char *)l4 + sizeof(struct udphdr)) > data_end)
        RETURN_TC_OK();

    __u16 *sportp = 0, *dportp = 0, *checkp = 0;
    if (parse_l4(l4, data_end, proto, &sportp, &dportp, &checkp) < 0)
    {
        debug_inc(DEBUG_TC_PARSE_FAIL);
        RETURN_TC_OK();
    }

    __u16 sport = *sportp;
    __u16 dport = *dportp;

    __u16 dport_host = bpf_ntohs(dport);
    if (dport_host >= SNAT_PORT_BASE)
    {
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
            debug_inc(DEBUG_TC_REVERSE_HIT);
            __u32 old_saddr = iph->saddr;
            __u32 old_daddr = iph->daddr;
            __u32 new_saddr = rval->vip;
            __u32 new_daddr = rval->client_ip;
            __u16 old_sport = sport;
            __u16 old_dport = dport;
            __u16 new_sport = rval->service_port;
            __u16 new_dport = rval->client_port;
            __u32 l3_off = sizeof(*eth);
            __u32 ip_check_off = l3_off + offsetof(struct iphdr, check);
            __u32 saddr_off = l3_off + offsetof(struct iphdr, saddr);
            __u32 daddr_off = l3_off + offsetof(struct iphdr, daddr);
            __u32 sport_off = l3_off + ihl_bytes;
            __u32 dport_off = sport_off + sizeof(__u16);
            __u32 l4_check_off = l3_off + ihl_bytes +
                                 (proto == IPPROTO_TCP ? offsetof(struct tcphdr, check) : offsetof(struct udphdr, check));
            __u16 old_l4_csum = *checkp;

            if (tc_update_ip_csum(skb, ip_check_off, old_saddr, new_saddr, old_daddr, new_daddr) < 0)
                RETURN_TC_OK();
            if (tc_update_l4_csum(skb, proto, l4_check_off, old_l4_csum, old_saddr, new_saddr, old_daddr, new_daddr,
                                  old_sport, new_sport, old_dport, new_dport) < 0)
                RETURN_TC_OK();

            if (tc_store_bytes(skb, saddr_off, &new_saddr, sizeof(new_saddr)) < 0)
                RETURN_TC_OK();
            if (tc_store_bytes(skb, daddr_off, &new_daddr, sizeof(new_daddr)) < 0)
                RETURN_TC_OK();
            if (tc_store_ports(skb, sport_off, new_sport, dport_off, new_dport) < 0)
                RETURN_TC_OK();
            if (tc_store_bytes(skb, offsetof(struct ethhdr, h_dest), rval->client_mac, 6) < 0)
                RETURN_TC_OK();
            if (tc_store_bytes(skb, offsetof(struct ethhdr, h_source), rval->relay_mac, 6) < 0)
                RETURN_TC_OK();

            __u32 tx_ifindex = rval->client_ifindex ? rval->client_ifindex : skb->ifindex;
            debug_inc(DEBUG_TC_REDIRECT);
            return tc_redirect_tx(tx_ifindex);
        }
        debug_inc(DEBUG_TC_REVERSE_MISS);
        debug_set(DEBUG_TC_LAST_REVERSE_MISS_DPORT, dport_host);
        debug_set(DEBUG_TC_LAST_REVERSE_MISS_IFINDEX, skb->ifindex);
        debug_set(DEBUG_TC_LAST_REVERSE_MISS_DADDR, iph->daddr);
    }

    struct fwd_key fkey = {
        .vip = iph->daddr,
        .client_ip = iph->saddr,
        .service_port = dport,
        .client_port = sport,
        .proto = proto,
    };

    struct fwd_val *fval = bpf_map_lookup_elem(&fwd_map, &fkey);
    struct fwd_val new_fval = {};

    if (!fval)
    {
        struct relay_rule *rule = bpf_map_lookup_elem(&config_map, &dport);
        if (!rule)
        {
            debug_inc(DEBUG_TC_NO_RULE);
            debug_set(DEBUG_TC_LAST_NO_RULE_DPORT, dport_host);
            debug_set(DEBUG_TC_LAST_NO_RULE_IFINDEX, skb->ifindex);
            debug_set(DEBUG_TC_LAST_NO_RULE_DADDR, iph->daddr);
            RETURN_TC_OK();
        }

        if (rule->relay_ifindex != 0 && rule->relay_ifindex != skb->ifindex)
        {
            debug_inc(DEBUG_TC_IF_MISMATCH);
            RETURN_TC_OK();
        }

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
            debug_inc(DEBUG_TC_FORWARD_NEW);
            fval = &new_fval;
        }
    }
    else
    {
        debug_inc(DEBUG_TC_FORWARD_REUSE);
    }

    __u32 old_saddr = iph->saddr;
    __u32 old_daddr = iph->daddr;
    __u32 new_saddr = fval->snat_ip;
    __u32 new_daddr = fval->target_ip;
    __u16 old_sport = sport;
    __u16 old_dport = dport;
    __u16 new_sport = fval->snat_port;
    __u16 new_dport = fval->target_port;
    __u32 l3_off = sizeof(*eth);
    __u32 ip_check_off = l3_off + offsetof(struct iphdr, check);
    __u32 saddr_off = l3_off + offsetof(struct iphdr, saddr);
    __u32 daddr_off = l3_off + offsetof(struct iphdr, daddr);
    __u32 sport_off = l3_off + ihl_bytes;
    __u32 dport_off = sport_off + sizeof(__u16);
    __u32 l4_check_off = l3_off + ihl_bytes +
                         (proto == IPPROTO_TCP ? offsetof(struct tcphdr, check) : offsetof(struct udphdr, check));
    __u16 old_l4_csum = *checkp;

    if (tc_update_ip_csum(skb, ip_check_off, old_saddr, new_saddr, old_daddr, new_daddr) < 0)
        RETURN_TC_OK();
    if (tc_update_l4_csum(skb, proto, l4_check_off, old_l4_csum, old_saddr, new_saddr, old_daddr, new_daddr,
                          old_sport, new_sport, old_dport, new_dport) < 0)
        RETURN_TC_OK();

    if (tc_store_bytes(skb, saddr_off, &new_saddr, sizeof(new_saddr)) < 0)
        RETURN_TC_OK();
    if (tc_store_bytes(skb, daddr_off, &new_daddr, sizeof(new_daddr)) < 0)
        RETURN_TC_OK();
    if (tc_store_ports(skb, sport_off, new_sport, dport_off, new_dport) < 0)
        RETURN_TC_OK();
    if (tc_store_bytes(skb, offsetof(struct ethhdr, h_dest), fval->next_hop_mac, 6) < 0)
        RETURN_TC_OK();
    if (tc_store_bytes(skb, offsetof(struct ethhdr, h_source), fval->relay_mac, 6) < 0)
        RETURN_TC_OK();

    __u32 tx_ifindex = fval->tx_ifindex ? fval->tx_ifindex : skb->ifindex;
    debug_inc(DEBUG_TC_REDIRECT);
    return tc_redirect_tx(tx_ifindex);
}

char _license[] SEC("license") = "GPL";
