#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Defines number of CPUs in the system. This can be set to a lower value than
// available CPUs
#define MAX_CPU 8

#define PPPOE_P_IP 0x0021
#define PPPOE_P_IPV6 0x0057
#define IP_TCP 0x06
#define IP_UDP 0x11

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(max_entries, MAX_CPU);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} cpu_map SEC(".maps");

typedef struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
} vlan_hdr;

typedef struct pppoe_hdr {
    __u8 version : 4;
    __u8 type : 4;
    __u8 code;
    __u16 session_id;
    __u16 length;
    __u16 protocol;
} pppoe_hdr;

typedef struct __attribute__((packed)) tuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u16 header_len;
} tuple;

// Calculates CRC "hash" for the flow
static __always_inline __u32 crc32(const void *data, __u64 len) {
    const unsigned char *p = data;
    __u32 crc = 0xFFFFFFFF;

    for (__u64 i = 0; i < len; i++) {
        crc ^= p[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc = crc >> 1;
        }
    }

    return ~crc;
}

// Calculates XDP data offsets and handles out of bounds check
__always_inline void *__offset(void *start, void *end, __u32 offset, __u32 len) {
    void *ptr = start + offset;

    if (ptr + len > end) {
        return NULL;
    }

    return ptr;
}

// Extracts IPv4 L3 information for the hash
__always_inline int __ipv4(void *data, void *data_end, tuple *tuple) {
    struct iphdr *ip;

    if (ip = __offset(data, data_end, 0, sizeof(struct iphdr)), ip == NULL) {
        return -1;
    }

    tuple->saddr = ip->saddr;
    tuple->daddr = ip->daddr;
    tuple->proto = ip->protocol;
    tuple->header_len = ip->ihl * 4;

    return 0;
}

// Extracts IPv6 L3 information for the hash, by folding v6 addresses into
// 32-bit values
__always_inline int __ipv6(void *data, void *data_end, tuple *tuple) {
    struct ipv6hdr *ip;
    int *saddr_ptr;
    int *daddr_ptr;

    if (ip = __offset(data, data_end, 0, sizeof(struct ipv6hdr)), ip == NULL) {
        return -1;
    }

    saddr_ptr = (int *)&ip->saddr.in6_u.u6_addr32;
    tuple->saddr ^= saddr_ptr[0];
    tuple->saddr ^= saddr_ptr[1];
    tuple->saddr ^= saddr_ptr[2];
    tuple->saddr ^= saddr_ptr[3];

    daddr_ptr = (int *)&ip->daddr.in6_u.u6_addr32;
    tuple->daddr ^= daddr_ptr[0];
    tuple->daddr ^= daddr_ptr[1];
    tuple->daddr ^= daddr_ptr[2];
    tuple->daddr ^= daddr_ptr[3];

    tuple->header_len = sizeof(struct ipv6hdr);
    tuple->proto = ip->nexthdr;

    return 0;
}

// Extracts TCP L4 information for the hash
__always_inline int __tcp(void *data, void *data_end, tuple *tuple) {
    struct tcphdr *tcp;

    if (tcp = __offset(data, data_end, 0, sizeof(struct tcphdr)), tcp == NULL) {
        return -1;
    }

    tuple->sport = tcp->source;
    tuple->dport = tcp->dest;

    return 0;
}

// Extracts UDP L4 information for the hash
__always_inline int __udp(void *data, void *data_end, tuple *tuple) {
    struct udphdr *udp;

    if (udp = __offset(data, data_end, 0, sizeof(struct udphdr)), udp == NULL) {
        return -1;
    }

    tuple->sport = udp->source;
    tuple->dport = udp->dest;

    return 0;
}

SEC("xdp") int start(struct xdp_md *ctx) {
    struct ethhdr *eth;
    vlan_hdr *vlan;
    pppoe_hdr *pppoe;
    tuple tuple;
    void *data_end;
    void *data;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // Make sure tuple is all zero
    __builtin_memset(&tuple, 0, sizeof(tuple));

    // Get pointer to ethernet header
    if (eth = __offset(data, data_end, 0, sizeof(struct ethhdr)), eth == NULL) {
        return XDP_PASS;
    }

    // We only support VLAN-tagged packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_8021Q) {
        return XDP_PASS;
    }

    // Get pointer to VLAN header
    if (vlan = __offset(eth, data_end, sizeof(struct ethhdr), sizeof(vlan_hdr)), vlan == NULL) {
        return XDP_PASS;
    }

    // We only care about PPP Session data
    if (bpf_ntohs(vlan->h_vlan_encapsulated_proto) != ETH_P_PPP_SES) {
        return XDP_PASS;
    }

    // Get pointer to PPPoE header
    if (pppoe = __offset(vlan, data_end, sizeof(vlan_hdr), sizeof(pppoe_hdr)), pppoe == NULL) {
        return XDP_PASS;
    }

    // We only support IPv4 and IPv6 packets
    if (bpf_ntohs(pppoe->protocol) != PPPOE_P_IP &&
        bpf_ntohs(pppoe->protocol) != PPPOE_P_IPV6) {
        return XDP_PASS;
    }

    // Extract L3 data for the hash
    switch (bpf_ntohs(pppoe->protocol)) {
        case PPPOE_P_IP:
            if (__ipv4((void *)pppoe + sizeof(pppoe_hdr), data_end, &tuple) < 0) {
                return XDP_PASS;
            }
            break;
        case PPPOE_P_IPV6:
            if (__ipv6((void *)pppoe + sizeof(pppoe_hdr), data_end, &tuple) < 0) {
                return XDP_PASS;
            }
            break;
    }

    // We only support TCP and UDP packets
    if (tuple.proto != IPPROTO_TCP && tuple.proto != IPPROTO_UDP) {
        return XDP_PASS;
    }

    void *proto_start = (void *)pppoe + sizeof(pppoe_hdr) + tuple.header_len;

    switch (tuple.proto) {
        case IPPROTO_TCP:
            if (__tcp(proto_start, data_end, &tuple) < 0) {
                return XDP_PASS;
            }
            break;
        case IPPROTO_UDP:
            if (__udp(proto_start, data_end, &tuple) < 0) {
                return XDP_PASS;
            }
            break;
    }

    // Calculate CPU for the packet
    __u32 cpu = crc32(&tuple, 12) % MAX_CPU;

    return bpf_redirect_map(&cpu_map, cpu, 0);
}

char LICENSE[] SEC("license") = "GPL";