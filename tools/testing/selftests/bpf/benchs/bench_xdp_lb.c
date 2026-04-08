// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Userspace driver for the XDP load-balancer benchmark.
 *
 * Usage:
 *   sudo ./bench -p 1 -d 5 xdp-lb --scenario tcp-v4-lru-hit
 *   sudo ./bench xdp-lb --list-scenarios
 *   sudo ./bench xdp-lb --batch-iters 50000 --scenario tcp-v6-lru-hit
 */

#include <argp.h>
#include <math.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bench.h"
#include "xdp_lb_bench.skel.h"
#include "xdp_lb_bench_common.h"
#include "bpf_util.h"

#define IP4(a, b, c, d) (((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d))

#define IP6(a, b, c, d)  { (__u32)(a), (__u32)(b), (__u32)(c), (__u32)(d) }

#define TNL_DST		IP4(192, 168, 1, 2)
#define REAL_INDEX	1
#define REAL_INDEX_V6	2
#define MAX_PKT_SIZE	256
#define IP_MF		0x2000

static const __u32 tnl_dst_v6[4] = { 0xfd000000, 0, 0, 2 };

static const __u8 lb_mac[ETH_ALEN]     = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static const __u8 client_mac[ETH_ALEN]  = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
static const __u8 router_mac[ETH_ALEN]  = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};

enum scenario_id {
	S_TCP_V4_LRU_HIT,
	S_TCP_V4_CH,
	S_TCP_V6_LRU_HIT,
	S_TCP_V6_CH,
	S_UDP_V4_LRU_HIT,
	S_UDP_V6_LRU_HIT,
	S_TCP_V4V6_LRU_HIT,
	S_TCP_V4_LRU_DIVERSE,
	S_TCP_V4_CH_DIVERSE,
	S_TCP_V6_LRU_DIVERSE,
	S_TCP_V6_CH_DIVERSE,
	S_UDP_V4_LRU_DIVERSE,
	S_TCP_V4_LRU_MISS,
	S_UDP_V4_LRU_MISS,
	S_TCP_V4_LRU_WARMUP,
	S_PASS_V4_NO_VIP,
	S_PASS_NON_IP,
	S_DROP_V4_FRAG,
	NUM_SCENARIOS,
};

struct test_scenario {
	const char *name;
	const char *description;
	int         expected_retval;
	bool        expect_encap;
	bool        is_v6;
	__u32       vip_addr;
	__u32       src_addr;
	__u32       tunnel_dst;
	__u32       vip_addr_v6[4];
	__u32       src_addr_v6[4];
	__u32       tunnel_dst_v6[4];
	__u16       dst_port;
	__u16       src_port;
	__u8        ip_proto;
	__u32       vip_flags;
	__u32       vip_num;
	bool        prepopulate_lru;
	bool        set_frag;
	__u16       eth_proto;
	bool        encap_v6_outer;
	__u32       flow_mask;
	bool        cold_lru;
};

static const struct test_scenario scenarios[NUM_SCENARIOS] = {
	[S_TCP_V4_LRU_HIT] = {
		.name            = "tcp-v4-lru-hit",
		.description     = "IPv4 TCP, LRU hit, IPIP encap",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.vip_addr        = IP4(10, 10, 1, 1),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr        = IP4(10, 10, 2, 1),
		.src_port        = 12345,
		.prepopulate_lru = true,
		.tunnel_dst      = TNL_DST,
	},
	[S_TCP_V4_CH] = {
		.name            = "tcp-v4-ch",
		.description     = "IPv4 TCP, CH (LRU bypass), IPIP encap",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.vip_addr        = IP4(10, 10, 1, 2),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr        = IP4(10, 10, 2, 2),
		.src_port        = 54321,
		.vip_flags       = F_LRU_BYPASS,
		.vip_num         = 1,
		.tunnel_dst      = TNL_DST,
	},
	[S_TCP_V6_LRU_HIT] = {
		.name            = "tcp-v6-lru-hit",
		.description     = "IPv6 TCP, LRU hit, IP6IP6 encap",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.is_v6           = true,
		.vip_addr_v6     = IP6(0xfd000100, 0, 0, 1),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr_v6     = IP6(0xfd000200, 0, 0, 1),
		.src_port        = 12345,
		.vip_num         = 10,
		.prepopulate_lru = true,
		.tunnel_dst_v6   = { 0xfd000000, 0, 0, 2 },
		.encap_v6_outer  = true,
	},
	[S_TCP_V6_CH] = {
		.name            = "tcp-v6-ch",
		.description     = "IPv6 TCP, CH (LRU bypass), IP6IP6 encap",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.is_v6           = true,
		.vip_addr_v6     = IP6(0xfd000100, 0, 0, 2),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr_v6     = IP6(0xfd000200, 0, 0, 2),
		.src_port        = 54321,
		.vip_flags       = F_LRU_BYPASS,
		.vip_num         = 12,
		.tunnel_dst_v6   = { 0xfd000000, 0, 0, 2 },
		.encap_v6_outer  = true,
	},
	[S_UDP_V4_LRU_HIT] = {
		.name            = "udp-v4-lru-hit",
		.description     = "IPv4 UDP, LRU hit, IPIP encap",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.vip_addr        = IP4(10, 10, 1, 1),
		.dst_port        = 443,
		.ip_proto        = IPPROTO_UDP,
		.src_addr        = IP4(10, 10, 3, 1),
		.src_port        = 11111,
		.vip_num         = 2,
		.prepopulate_lru = true,
		.tunnel_dst      = TNL_DST,
	},
	[S_UDP_V6_LRU_HIT] = {
		.name            = "udp-v6-lru-hit",
		.description     = "IPv6 UDP, LRU hit, IP6IP6 encap",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.is_v6           = true,
		.vip_addr_v6     = IP6(0xfd000100, 0, 0, 1),
		.dst_port        = 443,
		.ip_proto        = IPPROTO_UDP,
		.src_addr_v6     = IP6(0xfd000200, 0, 0, 3),
		.src_port        = 22222,
		.vip_num         = 14,
		.prepopulate_lru = true,
		.tunnel_dst_v6   = { 0xfd000000, 0, 0, 2 },
		.encap_v6_outer  = true,
	},
	[S_TCP_V4V6_LRU_HIT] = {
		.name            = "tcp-v4v6-lru-hit",
		.description     = "IPv4 TCP, LRU hit, IPv4-in-IPv6 encap",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.vip_addr        = IP4(10, 10, 1, 4),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr        = IP4(10, 10, 2, 4),
		.src_port        = 12347,
		.vip_num         = 13,
		.prepopulate_lru = true,
		.tunnel_dst_v6   = { 0xfd000000, 0, 0, 2 },
		.encap_v6_outer  = true,
	},
	[S_TCP_V4_LRU_DIVERSE] = {
		.name            = "tcp-v4-lru-diverse",
		.description     = "IPv4 TCP, diverse flows, warm LRU",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.vip_addr        = IP4(10, 10, 1, 1),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr        = IP4(10, 10, 2, 1),
		.src_port        = 12345,
		.prepopulate_lru = true,
		.tunnel_dst      = TNL_DST,
		.flow_mask       = 0xFFF,
	},
	[S_TCP_V4_CH_DIVERSE] = {
		.name            = "tcp-v4-ch-diverse",
		.description     = "IPv4 TCP, diverse flows, CH (LRU bypass)",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.vip_addr        = IP4(10, 10, 1, 2),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr        = IP4(10, 10, 2, 2),
		.src_port        = 54321,
		.vip_flags       = F_LRU_BYPASS,
		.vip_num         = 1,
		.tunnel_dst      = TNL_DST,
		.flow_mask       = 0xFFF,
	},
	[S_TCP_V6_LRU_DIVERSE] = {
		.name            = "tcp-v6-lru-diverse",
		.description     = "IPv6 TCP, diverse flows, warm LRU",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.is_v6           = true,
		.vip_addr_v6     = IP6(0xfd000100, 0, 0, 1),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr_v6     = IP6(0xfd000200, 0, 0, 1),
		.src_port        = 12345,
		.vip_num         = 10,
		.prepopulate_lru = true,
		.tunnel_dst_v6   = { 0xfd000000, 0, 0, 2 },
		.encap_v6_outer  = true,
		.flow_mask       = 0xFFF,
	},
	[S_TCP_V6_CH_DIVERSE] = {
		.name            = "tcp-v6-ch-diverse",
		.description     = "IPv6 TCP, diverse flows, CH (LRU bypass)",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.is_v6           = true,
		.vip_addr_v6     = IP6(0xfd000100, 0, 0, 2),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr_v6     = IP6(0xfd000200, 0, 0, 2),
		.src_port        = 54321,
		.vip_flags       = F_LRU_BYPASS,
		.vip_num         = 12,
		.tunnel_dst_v6   = { 0xfd000000, 0, 0, 2 },
		.encap_v6_outer  = true,
		.flow_mask       = 0xFFF,
	},
	[S_UDP_V4_LRU_DIVERSE] = {
		.name            = "udp-v4-lru-diverse",
		.description     = "IPv4 UDP, diverse flows, warm LRU",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.vip_addr        = IP4(10, 10, 1, 1),
		.dst_port        = 443,
		.ip_proto        = IPPROTO_UDP,
		.src_addr        = IP4(10, 10, 3, 1),
		.src_port        = 11111,
		.vip_num         = 2,
		.prepopulate_lru = true,
		.tunnel_dst      = TNL_DST,
		.flow_mask       = 0xFFF,
	},
	[S_TCP_V4_LRU_MISS] = {
		.name            = "tcp-v4-lru-miss",
		.description     = "IPv4 TCP, LRU miss (16M flow space), CH lookup",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.vip_addr        = IP4(10, 10, 1, 1),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr        = IP4(10, 10, 2, 1),
		.src_port        = 12345,
		.tunnel_dst      = TNL_DST,
		.flow_mask       = 0xFFFFFF,
		.cold_lru        = true,
	},
	[S_UDP_V4_LRU_MISS] = {
		.name            = "udp-v4-lru-miss",
		.description     = "IPv4 UDP, LRU miss (16M flow space), CH lookup",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.vip_addr        = IP4(10, 10, 1, 1),
		.dst_port        = 443,
		.ip_proto        = IPPROTO_UDP,
		.src_addr        = IP4(10, 10, 3, 1),
		.src_port        = 11111,
		.vip_num         = 2,
		.tunnel_dst      = TNL_DST,
		.flow_mask       = 0xFFFFFF,
		.cold_lru        = true,
	},
	[S_TCP_V4_LRU_WARMUP] = {
		.name            = "tcp-v4-lru-warmup",
		.description     = "IPv4 TCP, 4K flows, ~50% LRU miss (batch_iters=6500)",
		.expected_retval = XDP_TX,
		.expect_encap    = true,
		.vip_addr        = IP4(10, 10, 1, 1),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr        = IP4(10, 10, 2, 1),
		.src_port        = 12345,
		.tunnel_dst      = TNL_DST,
		.flow_mask       = 0xFFF,
		.cold_lru        = true,
	},
	[S_PASS_V4_NO_VIP] = {
		.name            = "pass-v4-no-vip",
		.description     = "IPv4 TCP, unknown VIP, XDP_PASS",
		.expected_retval = XDP_PASS,
		.vip_addr        = IP4(10, 10, 9, 9),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr        = IP4(10, 10, 4, 1),
		.src_port        = 33333,
	},
	[S_PASS_NON_IP] = {
		.name            = "pass-non-ip",
		.description     = "Non-IP (ARP), earliest XDP_PASS exit",
		.expected_retval = XDP_PASS,
		.eth_proto       = ETH_P_ARP,
	},
	[S_DROP_V4_FRAG] = {
		.name            = "drop-v4-frag",
		.description     = "IPv4 fragmented, XDP_DROP",
		.expected_retval = XDP_DROP,
		.vip_addr        = IP4(10, 10, 1, 1),
		.dst_port        = 80,
		.ip_proto        = IPPROTO_TCP,
		.src_addr        = IP4(10, 10, 5, 1),
		.src_port        = 44444,
		.set_frag        = true,
	},
};

static __u8  pkt_buf[NUM_SCENARIOS][MAX_PKT_SIZE];
static __u32 pkt_len[NUM_SCENARIOS];

static int lru_inner_fds[NR_CPUS];
static int nr_inner_maps;

static struct ctx {
	struct xdp_lb_bench *skel;
	int prog_fd;
} ctx;

static struct {
	__u32 batch_iters;
	int   scenario;
} args = {
	.batch_iters = 1000,
	.scenario    = -1,
};

static __u16 ip_checksum(const void *hdr, int len)
{
	const __u16 *p = hdr;
	__u32 csum = 0;
	int i;

	for (i = 0; i < len / 2; i++)
		csum += p[i];

	while (csum >> 16)
		csum = (csum & 0xffff) + (csum >> 16);

	return ~csum;
}

static void htonl_v6(__be32 dst[4], const __u32 src[4])
{
	int i;

	for (i = 0; i < 4; i++)
		dst[i] = htonl(src[i]);
}

static __be32 create_encap_ipv4_src(__u16 port, __be32 src)
{
	__u32 ip_suffix = htons(port);

	ip_suffix <<= 16;
	ip_suffix ^= src;
	return (0xFFFF0000 & ip_suffix) | IPIP_V4_PREFIX;
}

static void create_encap_ipv6_src(__u16 port, __be32 src, __be32 *saddr)
{
	saddr[0] = IPIP_V6_PREFIX1;
	saddr[1] = IPIP_V6_PREFIX2;
	saddr[2] = IPIP_V6_PREFIX3;
	saddr[3] = src ^ port;
}

static void build_flow_key(struct flow_key *fk, const struct test_scenario *sc)
{
	memset(fk, 0, sizeof(*fk));
	if (sc->is_v6) {
		htonl_v6(fk->srcv6, sc->src_addr_v6);
		htonl_v6(fk->dstv6, sc->vip_addr_v6);
	} else {
		fk->src = htonl(sc->src_addr);
		fk->dst = htonl(sc->vip_addr);
	}
	fk->proto = sc->ip_proto;
	fk->ports = (__u32)htons(sc->src_port) | ((__u32)htons(sc->dst_port) << 16);
}

static void build_l4(const struct test_scenario *sc, __u8 *p, __u32 *off)
{
	if (sc->ip_proto == IPPROTO_TCP) {
		struct tcphdr tcp = {};

		tcp.source = htons(sc->src_port);
		tcp.dest   = htons(sc->dst_port);
		tcp.doff   = 5;
		tcp.window = htons(8192);
		memcpy(p + *off, &tcp, sizeof(tcp));
		*off += sizeof(tcp);
	} else if (sc->ip_proto == IPPROTO_UDP) {
		struct udphdr udp = {};

		udp.source = htons(sc->src_port);
		udp.dest   = htons(sc->dst_port);
		udp.len    = htons(sizeof(udp) + 16);
		memcpy(p + *off, &udp, sizeof(udp));
		*off += sizeof(udp);
	}
}

static void build_packet(int idx)
{
	const struct test_scenario *sc = &scenarios[idx];
	__u8 *p = pkt_buf[idx];
	struct ethhdr eth = {};
	__u16 proto;
	__u32 off = 0;

	memcpy(eth.h_dest, lb_mac, ETH_ALEN);
	memcpy(eth.h_source, client_mac, ETH_ALEN);

	if (sc->eth_proto)
		proto = sc->eth_proto;
	else if (sc->is_v6)
		proto = ETH_P_IPV6;
	else
		proto = ETH_P_IP;

	eth.h_proto = htons(proto);
	memcpy(p, &eth, sizeof(eth));
	off += sizeof(eth);

	if (proto != ETH_P_IP && proto != ETH_P_IPV6) {
		memcpy(p + off, "bench___payload!", 16);
		off += 16;
		pkt_len[idx] = off;
		return;
	}

	if (sc->is_v6) {
		struct ipv6hdr ip6h = {};
		__u32 ip6_off = off;

		ip6h.version  = 6;
		ip6h.nexthdr  = sc->set_frag ? 44 : sc->ip_proto;
		ip6h.hop_limit = 64;
		htonl_v6((__be32 *)&ip6h.saddr, sc->src_addr_v6);
		htonl_v6((__be32 *)&ip6h.daddr, sc->vip_addr_v6);
		off += sizeof(ip6h);

		if (sc->set_frag) {
			memset(p + off, 0, 8);
			p[off] = sc->ip_proto;
			off += 8;
		}

		build_l4(sc, p, &off);

		memcpy(p + off, "bench___payload!", 16);
		off += 16;

		ip6h.payload_len = htons(off - ip6_off - sizeof(ip6h));
		memcpy(p + ip6_off, &ip6h, sizeof(ip6h));
	} else {
		struct iphdr iph = {};
		__u32 ip_off = off;

		iph.version  = 4;
		iph.ihl      = 5;
		iph.ttl      = 64;
		iph.protocol = sc->ip_proto;
		iph.saddr    = htonl(sc->src_addr);
		iph.daddr    = htonl(sc->vip_addr);
		iph.frag_off = sc->set_frag ? htons(IP_MF) : 0;
		off += sizeof(iph);

		build_l4(sc, p, &off);

		memcpy(p + off, "bench___payload!", 16);
		off += 16;

		iph.tot_len = htons(off - ip_off);
		iph.check   = ip_checksum(&iph, sizeof(iph));
		memcpy(p + ip_off, &iph, sizeof(iph));
	}

	pkt_len[idx] = off;
}

static void populate_vip(struct xdp_lb_bench *skel, const struct test_scenario *sc)
{
	struct vip_definition key = {};
	struct vip_meta val = {};
	int err;

	if (sc->is_v6)
		htonl_v6(key.vipv6, sc->vip_addr_v6);
	else
		key.vip = htonl(sc->vip_addr);
	key.port  = htons(sc->dst_port);
	key.proto = sc->ip_proto;
	val.flags   = sc->vip_flags;
	val.vip_num = sc->vip_num;

	err = bpf_map_update_elem(bpf_map__fd(skel->maps.vip_map), &key, &val, BPF_ANY);
	if (err) {
		fprintf(stderr, "vip_map [%s]: %s\n", sc->name, strerror(errno));
		exit(1);
	}
}

static void create_per_cpu_lru_maps(struct xdp_lb_bench *skel)
{
	int outer_fd = bpf_map__fd(skel->maps.lru_mapping);
	unsigned int nr_cpus = bpf_num_possible_cpus();
	int i, inner_fd, err;
	__u32 cpu;

	if (nr_cpus > NR_CPUS)
		nr_cpus = NR_CPUS;

	for (i = 0; i < (int)nr_cpus; i++) {
		LIBBPF_OPTS(bpf_map_create_opts, opts);

		inner_fd = bpf_map_create(BPF_MAP_TYPE_LRU_HASH, "lru_inner",
					  sizeof(struct flow_key),
					  sizeof(struct real_pos_lru),
					  DEFAULT_LRU_SIZE, &opts);
		if (inner_fd < 0) {
			fprintf(stderr, "lru_inner[%d]: %s\n", i, strerror(errno));
			exit(1);
		}

		cpu = i;
		err = bpf_map_update_elem(outer_fd, &cpu, &inner_fd, BPF_ANY);
		if (err) {
			fprintf(stderr, "lru_mapping[%d]: %s\n", i, strerror(errno));
			close(inner_fd);
			exit(1);
		}

		lru_inner_fds[i] = inner_fd;
	}

	nr_inner_maps = nr_cpus;
}

static void populate_lru(const struct test_scenario *sc, __u32 real_idx)
{
	struct real_pos_lru lru = { .pos = real_idx };
	struct flow_key fk;
	int i, err;

	build_flow_key(&fk, sc);

	/* Insert into every per-CPU inner LRU so the entry is found
	 * regardless of which CPU runs the BPF program.
	 */
	for (i = 0; i < nr_inner_maps; i++) {
		err = bpf_map_update_elem(lru_inner_fds[i], &fk, &lru, BPF_ANY);
		if (err) {
			fprintf(stderr, "lru_inner[%d] [%s]: %s\n", i, sc->name,
				strerror(errno));
			exit(1);
		}
	}
}

static void populate_maps(struct xdp_lb_bench *skel)
{
	struct real_definition real_v4 = {};
	struct real_definition real_v6 = {};
	struct ctl_value cval = {};
	__u32 key, real_idx = REAL_INDEX;
	int ch_fd, err, i;

	for (i = 0; i < NUM_SCENARIOS; i++) {
		if (scenarios[i].expect_encap)
			populate_vip(skel, &scenarios[i]);
	}

	ch_fd = bpf_map__fd(skel->maps.ch_rings);
	for (i = 0; i < CH_RINGS_SIZE; i++) {
		__u32 k = i;

		err = bpf_map_update_elem(ch_fd, &k, &real_idx, BPF_ANY);
		if (err) {
			fprintf(stderr, "ch_rings[%d]: %s\n", i, strerror(errno));
			exit(1);
		}
	}

	memcpy(cval.mac, router_mac, ETH_ALEN);
	key = 0;
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.ctl_array), &key, &cval, BPF_ANY);
	if (err) {
		fprintf(stderr, "ctl_array: %s\n", strerror(errno));
		exit(1);
	}

	key = REAL_INDEX;
	real_v4.dst = htonl(TNL_DST);
	htonl_v6(real_v4.dstv6, tnl_dst_v6);
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.reals), &key, &real_v4, BPF_ANY);
	if (err) {
		fprintf(stderr, "reals[%d]: %s\n", REAL_INDEX, strerror(errno));
		exit(1);
	}

	key = REAL_INDEX_V6;
	htonl_v6(real_v6.dstv6, tnl_dst_v6);
	real_v6.flags = F_IPV6;
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.reals), &key, &real_v6, BPF_ANY);
	if (err) {
		fprintf(stderr, "reals[%d]: %s\n", REAL_INDEX_V6, strerror(errno));
		exit(1);
	}

	create_per_cpu_lru_maps(skel);

	for (i = 0; i < NUM_SCENARIOS; i++) {
		const struct test_scenario *sc = &scenarios[i];
		__u32 ridx;

		if (!sc->prepopulate_lru)
			continue;

		ridx = sc->encap_v6_outer ? REAL_INDEX_V6 : REAL_INDEX;
		populate_lru(sc, ridx);
	}

	/* Track per-real LRU misses for the tcp-v4-lru-hit VIP */
	{
		const struct test_scenario *sc = &scenarios[S_TCP_V4_LRU_HIT];
		struct vip_definition miss_vip = {};

		miss_vip.vip = htonl(sc->vip_addr);
		miss_vip.port = htons(sc->dst_port);
		miss_vip.proto = sc->ip_proto;

		key = 0;
		err = bpf_map_update_elem(bpf_map__fd(skel->maps.vip_miss_stats),
					  &key, &miss_vip, BPF_ANY);
		if (err) {
			fprintf(stderr, "vip_miss_stats: %s\n", strerror(errno));
			exit(1);
		}
	}
}

static bool validate_encap_v4(const struct test_scenario *sc, const __u8 *out, __u32 out_len,
			      const __u8 *in, __u32 in_len)
{
	__u32 expected = in_len + sizeof(struct iphdr);
	struct ethhdr *new_eth = (void *)out;
	struct iphdr *outer;
	__u16 saved_check, computed;
	__u32 inner_off, orig_off, cmp_len;

	if (out_len != expected) {
		fprintf(stderr, "  [%s] FAIL: output %u, expected %u\n", sc->name, out_len, expected);
		return false;
	}

	outer = (void *)(out + sizeof(struct ethhdr));

	if (outer->protocol != IPPROTO_IPIP) {
		fprintf(stderr, "  [%s] FAIL: outer proto %d, expected %d\n",
			sc->name, outer->protocol, IPPROTO_IPIP);
		return false;
	}

	if (ntohl(outer->daddr) != sc->tunnel_dst) {
		fprintf(stderr, "  [%s] FAIL: tunnel dst %08x, expected %08x\n",
			sc->name, ntohl(outer->daddr), sc->tunnel_dst);
		return false;
	}

	if (outer->saddr != create_encap_ipv4_src(htons(sc->src_port), htonl(sc->src_addr))) {
		fprintf(stderr, "  [%s] FAIL: tunnel src mismatch\n", sc->name);
		return false;
	}

	inner_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
	orig_off  = sizeof(struct ethhdr);
	cmp_len   = in_len - sizeof(struct ethhdr);

	if (memcmp(out + inner_off, in + orig_off, cmp_len) != 0) {
		fprintf(stderr, "  [%s] FAIL: inner packet mismatch\n", sc->name);
		return false;
	}

	saved_check = outer->check;
	outer->check = 0;
	computed = ip_checksum(outer, sizeof(struct iphdr));
	if (saved_check != computed) {
		fprintf(stderr, "  [%s] FAIL: outer csum %04x, expected %04x\n",
			sc->name, ntohs(saved_check), ntohs(computed));
		return false;
	}
	outer->check = saved_check;

	if (memcmp(new_eth->h_dest, router_mac, ETH_ALEN) != 0) {
		fprintf(stderr, "  [%s] FAIL: dst MAC mismatch\n", sc->name);
		return false;
	}

	return true;
}

static bool validate_encap_v6(const struct test_scenario *sc, const __u8 *out, __u32 out_len,
			      const __u8 *in, __u32 in_len, __u8 expected_nexthdr)
{
	__u32 expected = in_len + sizeof(struct ipv6hdr);
	struct ethhdr *new_eth = (void *)out;
	struct ipv6hdr *outer;
	__be32 expected_src[4], expected_dst[4];
	__u32 inner_off, orig_off, cmp_len;

	if (out_len != expected) {
		fprintf(stderr, "  [%s] FAIL: output %u, expected %u\n", sc->name, out_len, expected);
		return false;
	}

	outer = (void *)(out + sizeof(struct ethhdr));

	if (outer->version != 6) {
		fprintf(stderr, "  [%s] FAIL: outer version %d, expected 6\n", sc->name, outer->version);
		return false;
	}

	if (outer->nexthdr != expected_nexthdr) {
		fprintf(stderr, "  [%s] FAIL: outer nexthdr %d, expected %d\n",
			sc->name, outer->nexthdr, expected_nexthdr);
		return false;
	}

	create_encap_ipv6_src(htons(sc->src_port),
			      sc->is_v6 ? htonl(sc->src_addr_v6[0]) : htonl(sc->src_addr),
			      expected_src);
	if (memcmp(&outer->saddr, expected_src, 16) != 0) {
		fprintf(stderr, "  [%s] FAIL: tunnel src v6 mismatch\n", sc->name);
		return false;
	}

	htonl_v6(expected_dst, sc->tunnel_dst_v6);
	if (memcmp(&outer->daddr, expected_dst, 16) != 0) {
		fprintf(stderr, "  [%s] FAIL: tunnel dst v6 mismatch\n", sc->name);
		return false;
	}

	inner_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
	orig_off  = sizeof(struct ethhdr);
	cmp_len   = in_len - sizeof(struct ethhdr);

	if (memcmp(out + inner_off, in + orig_off, cmp_len) != 0) {
		fprintf(stderr, "  [%s] FAIL: inner packet mismatch\n", sc->name);
		return false;
	}

	if (memcmp(new_eth->h_dest, router_mac, ETH_ALEN) != 0) {
		fprintf(stderr, "  [%s] FAIL: dst MAC mismatch\n", sc->name);
		return false;
	}

	if (ntohs(new_eth->h_proto) != ETH_P_IPV6) {
		fprintf(stderr, "  [%s] FAIL: eth proto %04x, expected IPv6\n",
			sc->name, ntohs(new_eth->h_proto));
		return false;
	}

	return true;
}

static bool validate_scenario(int idx)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	const struct test_scenario *sc = &scenarios[idx];
	__u8 out[MAX_PKT_SIZE + sizeof(struct ipv6hdr)];
	int err;

	topts.data_in      = pkt_buf[idx];
	topts.data_size_in = pkt_len[idx];
	topts.data_out      = out;
	topts.data_size_out = sizeof(out);
	topts.repeat        = 1;

	err = bpf_prog_test_run_opts(ctx.prog_fd, &topts);
	if (err) {
		fprintf(stderr, "  [%s] FAIL: test_run: %s\n", sc->name, strerror(errno));
		return false;
	}

	if ((int)topts.retval != sc->expected_retval) {
		fprintf(stderr, "  [%s] FAIL: retval %d, expected %d\n",
			sc->name, (int)topts.retval, sc->expected_retval);
		return false;
	}

	if (sc->expected_retval == XDP_DROP) {
		printf("  [%s] PASS  (XDP_DROP) %s\n",
		       sc->name, sc->description);
		return true;
	}

	if (sc->expected_retval == XDP_PASS) {
		if (topts.data_size_out != pkt_len[idx] ||
		    memcmp(out, pkt_buf[idx], pkt_len[idx]) != 0) {
			fprintf(stderr, "  [%s] FAIL: XDP_PASS output != input\n", sc->name);
			return false;
		}
		printf("  [%s] PASS  (XDP_PASS) %s\n",
		       sc->name, sc->description);
		return true;
	}

	if (sc->encap_v6_outer) {
		__u8 nexthdr = sc->is_v6 ? IPPROTO_IPV6 : IPPROTO_IPIP;

		if (!validate_encap_v6(sc, out, topts.data_size_out, pkt_buf[idx], pkt_len[idx], nexthdr))
			return false;
	} else {
		if (!validate_encap_v4(sc, out, topts.data_size_out, pkt_buf[idx], pkt_len[idx]))
			return false;
	}

	printf("  [%s] PASS  (XDP_TX) %s\n", sc->name, sc->description);
	return true;
}

static int find_scenario(const char *name)
{
	int i;

	for (i = 0; i < NUM_SCENARIOS; i++) {
		if (strcmp(scenarios[i].name, name) == 0)
			return i;
	}
	return -1;
}

static void xdp_lb_validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "benchmark doesn't support consumers\n");
		exit(1);
	}
}

static void xdp_lb_setup(void)
{
	struct xdp_lb_bench *skel;
	int err, i;

	if (args.scenario < 0) {
		fprintf(stderr, "--scenario is required. Use --list-scenarios to see options.\n");
		exit(1);
	}

	setup_libbpf();

	skel = xdp_lb_bench__open();
	if (!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	skel->rodata->batch_iters = args.batch_iters;

	err = xdp_lb_bench__load(skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton: %s\n", strerror(-err));
		xdp_lb_bench__destroy(skel);
		exit(1);
	}

	ctx.skel    = skel;
	ctx.prog_fd = bpf_program__fd(skel->progs.xdp_lb_bench);

	for (i = 0; i < NUM_SCENARIOS; i++)
		build_packet(i);

	populate_maps(skel);

	printf("Validating scenario '%s' (batch_iters=%u):\n", scenarios[args.scenario].name,
	       args.batch_iters);

	if (!validate_scenario(args.scenario)) {
		fprintf(stderr, "\nValidation FAILED - aborting benchmark\n");
		exit(1);
	}

	if (scenarios[args.scenario].flow_mask) {
		skel->bss->flow_mask = scenarios[args.scenario].flow_mask;
		printf("  Flow diversity: %u unique src addrs (mask 0x%x)\n",
		       scenarios[args.scenario].flow_mask + 1,
		       scenarios[args.scenario].flow_mask);
	}
	if (scenarios[args.scenario].cold_lru) {
		skel->bss->cold_lru = 1;
		printf("  Cold LRU: enabled (per-batch generation)\n");
	}

	printf("\nBenchmarking: %s\n\n", scenarios[args.scenario].name);
}

static void *xdp_lb_producer(void *input)
{
	int idx = args.scenario;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in      = pkt_buf[idx],
		.data_size_in = pkt_len[idx],
		.repeat       = 1,
	);

	while (true)
		bpf_prog_test_run_opts(ctx.prog_fd, &topts);

	return NULL;
}

static void xdp_lb_measure(struct bench_res *res)
{
	static int measure_calls;

	if (measure_calls++ == env.warmup_sec)
		ctx.skel->bss->timing_enabled = 1;
}

static int cmp_double(const void *a, const void *b)
{
	double da = *(const double *)a;
	double db = *(const double *)b;

	if (da < db) return -1;
	if (da > db) return 1;
	return 0;
}

#define HIST_BINS	30
#define HIST_BAR_WIDTH	40

static void print_histogram(const double *samples, int total, double p1, double p99, double mean)
{
	double hist_lo = p1, hist_hi = p99;
	double range = hist_hi - hist_lo;
	double half = range < 0.5 ? 0.25 : range;
	__u64 bins[HIST_BINS] = {};
	__u64 below = 0, above = 0, max_bin = 0;
	double bin_width;
	int i, j, prec;

	hist_lo = mean - half;
	hist_hi = mean + half;

	bin_width = (hist_hi - hist_lo) / HIST_BINS;

	if (bin_width >= 0.1)
		prec = 1;
	else if (bin_width >= 0.01)
		prec = 2;
	else
		prec = 3;

	for (i = 0; i < total; i++) {
		if (samples[i] < hist_lo) {
			below++;
		} else if (samples[i] >= hist_hi) {
			above++;
		} else {
			int b = (int)((samples[i] - hist_lo) / bin_width);

			if (b >= HIST_BINS)
				b = HIST_BINS - 1;
			bins[b]++;
			if (bins[b] > max_bin)
				max_bin = bins[b];
		}
	}

	printf("\n  Distribution (ns/op, p1..p99 range):\n");

	if (below > 0)
		printf("  %10s : %-8llu  (below range)\n", "<p1", (unsigned long long)below);

	for (i = 0; i < HIST_BINS; i++) {
		double lo;
		int bar_len;

		if (bins[i] == 0 && i > 0 && i < HIST_BINS - 1)
			continue;

		lo = hist_lo + i * bin_width;
		bar_len = max_bin > 0
			? (int)(bins[i] * HIST_BAR_WIDTH / max_bin)
			: 0;

		printf("  %10.*f : %-8llu  |", prec, lo, (unsigned long long)bins[i]);
		for (j = 0; j < HIST_BAR_WIDTH; j++)
			putchar(j < bar_len ? '*' : ' ');
		printf("|\n");
	}

	if (above > 0)
		printf("  %10s : %-8llu  (above range)\n", ">p99", (unsigned long long)above);
}

static void xdp_lb_report_final(struct bench_res res[], int res_cnt)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u32 timed_iters = args.batch_iters - 1;
	double *ns_per_op;
	double sum = 0, min_val, max_val, median, p1, p99, mean, stddev_val;
	int total = 0;
	int i, j, prec;

	printf("\nScenario: %s - %s\n",
	       scenarios[args.scenario].name, scenarios[args.scenario].description);
	printf("Batch size: %u iterations/invocation (%u timed)\n", args.batch_iters, timed_iters);

	ns_per_op = calloc(NR_CPUS * NR_SAMPLES, sizeof(double));
	if (!ns_per_op) {
		fprintf(stderr, "failed to allocate timing buffer\n");
		return;
	}

	for (i = 0; i < (int)nr_cpus && i < NR_CPUS; i++) {
		__u32 idx = ctx.skel->bss->timing_idx[i];
		__u32 count = idx < NR_SAMPLES ? idx : NR_SAMPLES;

		for (j = 0; j < (int)count; j++) {
			__u64 sample = ctx.skel->bss->timing_samples[i][j];

			if (sample == 0)
				continue;
			ns_per_op[total++] = (double)sample / timed_iters;
		}
	}

	if (total == 0) {
		printf("\nNo in-BPF timing samples collected.\n");
		free(ns_per_op);
		return;
	}

	qsort(ns_per_op, total, sizeof(double), cmp_double);

	min_val = ns_per_op[0];
	max_val = ns_per_op[total - 1];
	p1      = ns_per_op[(int)(total * 0.01)];
	median  = ns_per_op[total / 2];
	p99     = ns_per_op[(int)(total * 0.99)];

	for (i = 0; i < total; i++)
		sum += ns_per_op[i];
	mean = sum / total;

	stddev_val = 0;
	for (i = 0; i < total; i++) {
		double diff = ns_per_op[i] - mean;

		stddev_val += diff * diff;
	}
	stddev_val = sqrt(stddev_val / total);

	if (p99 - p1 >= 1.0)
		prec = 1;
	else if (p99 - p1 >= 0.1)
		prec = 2;
	else
		prec = 3;

	printf("\nIn-BPF timing: %d batch samples, %u ops/batch\n", total, timed_iters);
	printf("  avg %.*f ns/op, stddev %.*f ns, CV %.2f%%\n",
	       prec, mean, prec, stddev_val, stddev_val / mean * 100.0);
	printf("  min %.*f, p1 %.*f, median %.*f, p99 %.*f, max %.*f ns/op\n",
	       prec, min_val, prec, p1, prec, median, prec, p99, prec, max_val);

	print_histogram(ns_per_op, total, p1, p99, mean);

	free(ns_per_op);
}

enum {
	ARG_BATCH_ITERS    = 9000,
	ARG_SCENARIO       = 9001,
	ARG_LIST_SCENARIOS = 9002,
};

static const struct argp_option opts[] = {
	{ "batch-iters", ARG_BATCH_ITERS, "N", 0,
	  "Full-flow iterations per BPF invocation (default: 1000)" },
	{ "scenario", ARG_SCENARIO, "NAME", 0,
	  "Scenario to benchmark (required)" },
	{ "list-scenarios", ARG_LIST_SCENARIOS, NULL, 0,
	  "List available scenarios and exit" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long ret;
	int i;

	switch (key) {
	case ARG_BATCH_ITERS:
		ret = strtol(arg, NULL, 10);
		if (ret < 2 || ret > 1000000) {
			fprintf(stderr, "--batch-iters: must be 2..1000000\n");
			argp_usage(state);
		}
		args.batch_iters = ret;
		break;
	case ARG_SCENARIO:
		args.scenario = find_scenario(arg);
		if (args.scenario < 0) {
			fprintf(stderr, "unknown scenario: '%s'\n", arg);
			fprintf(stderr, "use --list-scenarios to see options\n");
			argp_usage(state);
		}
		break;
	case ARG_LIST_SCENARIOS:
		printf("Available scenarios:\n");
		for (i = 0; i < NUM_SCENARIOS; i++)
			printf("  %-20s  %s\n", scenarios[i].name, scenarios[i].description);
		exit(0);
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_xdp_lb_argp = {
	.options = opts,
	.parser  = parse_arg,
};

const struct bench bench_xdp_lb = {
	.name            = "xdp-lb",
	.argp            = &bench_xdp_lb_argp,
	.validate        = xdp_lb_validate,
	.setup           = xdp_lb_setup,
	.producer_thread = xdp_lb_producer,
	.measure         = xdp_lb_measure,
	.report_final    = xdp_lb_report_final,
};
