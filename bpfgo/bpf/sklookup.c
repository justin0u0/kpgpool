#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define FORMAT_IP(ip) \
	(ip) & 0xff, ((ip) >> 8) & 0xff, ((ip) >> 16) & 0xff, ((ip) >> 24) & 0xff

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 20);
	__type(key, __u64); // (ip << 32) | port
	__type(value, __u32);
} sockhash SEC(".maps");

SEC("sk_lookup/debug")
int debug(struct bpf_sk_lookup *ctx) {
	bpf_printk("[sk_lookup/debug] local [%d.%d.%d.%d:%d], remote [%d.%d.%d.%d:%d]",
		FORMAT_IP(ctx->local_ip4), ctx->local_port,
		FORMAT_IP(ctx->remote_ip4), bpf_ntohs(ctx->remote_port));

	__u64 key = ((__u64)bpf_ntohl(ctx->remote_ip4) << 32) | bpf_ntohs(ctx->remote_port);
	bpf_printk("[sk_lookup/debug] key %llu", key);

	__u64 zero = 0;
	struct bpf_sock *sk;
	sk = bpf_map_lookup_elem(&sockhash, &zero);
	if (!sk) {
		bpf_printk("[sk_lookup/debug] no socket found");
		return SK_PASS;
	}

	bpf_printk("[sk_lookup/debug] socket src [%d.%d.%d.%d:%d], dst [%d.%d.%d.%d:%d]",
		FORMAT_IP(sk->src_ip4), sk->src_port,
		FORMAT_IP(sk->dst_ip4), bpf_ntohs(sk->dst_port));

	bpf_sk_release(sk);

	return SK_PASS;
}

SEC("sk_lookup/redirect")
int redirect(struct bpf_sk_lookup *ctx) {
	__u64 key = ((__u64)bpf_ntohl(ctx->remote_ip4) << 32) | bpf_ntohs(ctx->remote_port);

	struct bpf_sock *sk;
	sk = bpf_map_lookup_elem(&sockhash, &key);
	if (!sk) {
		return SK_PASS;
	}

	bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);

	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
