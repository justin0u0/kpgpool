//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

#define FORMAT_IP(ip) \
	(ip) & 0xff, ((ip) >> 8) & 0xff, ((ip) >> 16) & 0xff, ((ip) >> 24) & 0xff

#define POOLER_PORT 6432
#define BACKEND_PORT 5432

#define ENABLE_FAST_REDIRECT
#define ENABLE_DEBUG

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;
typedef __s64 i64;
typedef __s32 i32;
typedef __s16 i16;
typedef __s8 i8;

struct socket_4_tuple {
	u32 local_ip4;		// network byte order
	u32 local_port;		// host byte order
	u32 remote_ip4;		// network byte order
	u32 remote_port;	// network byte order
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 1024);
	__type(key, struct socket_4_tuple);
	__type(value, u32); // socket FD
} sockmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct socket_4_tuple);
	__type(value, struct socket_4_tuple);
} pairs SEC(".maps");

SEC("sockops/prog")
int sockops_prog(struct bpf_sock_ops *skops) {
	u32 ret;

	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // SYN-ACK
#ifdef ENABLE_DEBUG
		bpf_printk("[BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB] local [%u.%u.%u.%u:%u], remote [%u.%u.%u.%u:%u]",
			FORMAT_IP(skops->local_ip4), skops->local_port,
			FORMAT_IP(skops->remote_ip4), bpf_ntohl(skops->remote_port));
		bpf_printk("[BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB] raw %x %x %x %x",
			skops->local_ip4, skops->local_port,
			skops->remote_ip4, skops->remote_port);
#endif

		if (skops->local_port == POOLER_PORT) {
			struct socket_4_tuple key = {
				.local_ip4 = skops->local_ip4,
				.local_port = skops->local_port,
				.remote_ip4 = skops->remote_ip4,
				.remote_port = skops->remote_port,
			};

			ret = bpf_sock_hash_update(skops, &sockmap, &key, BPF_ANY);
#ifdef ENABLE_DEBUG
			if (ret != 0) {
				bpf_printk("[BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB] sockmap update failed: %d", ret);
			} else {
				bpf_printk("[BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB] sockmap update");
			}
#endif
		}
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: // SYN
#ifdef ENABLE_DEBUG
		bpf_printk("[BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB] local [%u.%u.%u.%u:%u], remote [%u.%u.%u.%u:%u]",
			FORMAT_IP(skops->local_ip4), skops->local_port,
			FORMAT_IP(skops->remote_ip4), bpf_ntohl(skops->remote_port));
		bpf_printk("[BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB] raw %x %x %x %x",
			skops->local_ip4, skops->local_port,
			skops->remote_ip4, skops->remote_port);
#endif

		if (bpf_ntohl(skops->remote_port) == BACKEND_PORT) {
			struct socket_4_tuple key = {
				.local_ip4 = skops->local_ip4,
				.local_port = skops->local_port,
				.remote_ip4 = skops->remote_ip4,
				.remote_port = skops->remote_port,
			};
			ret = bpf_sock_hash_update(skops, &sockmap, &key, BPF_ANY);
#ifdef ENABLE_DEBUG
			if (ret != 0) {
				bpf_printk("[BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB] sockmap update failed: %d", ret);
			} else {
				bpf_printk("[BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB] sockmap update");
			}
#endif
		}
		break;
	}

	return 0;
}

SEC("sk_skb/stream_parser/prog")
int sk_skb_stream_parser_prog(struct __sk_buff *skb) {
#ifdef ENABLE_DEBUG
	bpf_printk("[sk_skb_stream_parser_prog] local [%u.%u.%u.%u:%u] | remote [%u.%u.%u.%u:%u] | len [%u] | data len [%u]",
		FORMAT_IP(skb->local_ip4), skb->local_port,
		FORMAT_IP(skb->remote_ip4), bpf_ntohl(skb->remote_port), skb->len, skb->data_end - skb->data);

	void* data = (void*)(long)skb->data;
	void* data_end = (void*)(long)skb->data_end;

	u8* code = (void*)data;
	if ((void*)(code + 1) > data_end) {
		bpf_printk("[sk_skb_stream_parser_prog] no code");
		return skb->len;
	}
	i32* len = (void*)(code + 1);
	if ((void*)(len + 1) > data_end) {
		bpf_printk("[sk_skb_stream_parser_prog] no len");
		return skb->len;
	}
	bpf_printk("[sk_skb_stream_parser_prog] code=[%u], len=[%d]", *code, bpf_ntohl(*len));
#endif

	return skb->len;
}

/*
int fallback_redirect(struct __sk_buff *skb, struct socket_4_tuple* key) {
	int ret = bpf_sk_redirect_hash(skb, &sockmap, key, BPF_F_INGRESS);
#ifdef ENABLE_DEBUG
	if (ret == 0) {
		bpf_printk("[sk_skb_stream_verdict_prog] sockmap redirect failed");
	} else {
		bpf_printk("[sk_skb_stream_verdict_prog] sockmap redirect");
	}
#endif
	return ret;
}
*/

SEC("sk_skb/stream_verdict/prog")
int sk_skb_stream_verdict_prog(struct __sk_buff *skb)
{
#ifdef ENABLE_DEBUG
	bpf_printk("[sk_skb_stream_verdict_prog] local [%u.%u.%u.%u:%u] | remote [%u.%u.%u.%u:%u] | len [%u] | data len [%u]",
		FORMAT_IP(skb->local_ip4), skb->local_port,
		FORMAT_IP(skb->remote_ip4), bpf_ntohl(skb->remote_port), skb->len, skb->data_end - skb->data);
#endif

	struct socket_4_tuple key = {
		.local_ip4 = skb->local_ip4,
		.local_port = skb->local_port,
		.remote_ip4 = skb->remote_ip4,
		.remote_port = skb->remote_port,
	};
	return bpf_sk_redirect_hash(skb, &sockmap, &key, BPF_F_INGRESS);

	/*
	void* data = (void*)(long)skb->data;
	void* data_end = (void*)(long)skb->data_end;

	u8* code = (void*)data;
	if ((void*)(code + 1) > data_end) {
#ifdef ENABLE_DEBUG
		bpf_printk("[sk_skb_stream_verdict_prog] no code");
#endif
		return fallback_redirect(skb, &key);
	}
	i32* len = (void*)(code + 1);
	if ((void*)(len + 1) > data_end) {
#ifdef ENABLE_DEBUG
		bpf_printk("[sk_skb_stream_verdict_prog] no len");
#endif
		return fallback_redirect(skb, &key);
	}

#ifdef ENABLE_DEBUG
	bpf_printk("[sk_skb_stream_verdict_prog] code=[%u], len=[%d]", *code, bpf_ntohl(*len));
#endif

#ifdef ENABLE_FAST_REDIRECT
	if (skb->local_port == POOLER_PORT) {
		if ((*code) == 'Q') {
#ifdef ENABLE_DEBUG
			bpf_printk("[sk_skb_stream_verdict_prog] Q: Query, should redirect to backend directly");
#endif
		}
	} else if (bpf_ntohl(skb->remote_port) == BACKEND_PORT) {
		if ((*code) == 'T' || (*code) == 'I' || (*code) == 'C') {
			// T: RowDescription
			// I: EmptyQueryResponse
			// C: CommandComplete
#ifdef ENABLE_DEBUG
			bpf_printk("[sk_skb_stream_verdict_prog] T/I/C: RowDescription/EmptyQueryResponse/CommandComplete, should redirect to client directly");
#endif
		}
	}
#endif

	return fallback_redirect(skb, &key);
	*/
}

char _license[] SEC("license") = "GPL";
