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
// #define ENABLE_DEBUG

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;
typedef __s64 i64;
typedef __s32 i32;
typedef __s16 i16;
typedef __s8 i8;

struct socket_4_tuple {
	u32 local_ip4;
	u32 local_port;
	u32 remote_ip4;
	u32 remote_port;
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 1024);
	__type(key, struct socket_4_tuple);
	__type(value, u32); // socket FD
} sockmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 1024);
	__type(value, struct socket_4_tuple);
} servers SEC(".maps");

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
			ret = bpf_map_push_elem(&servers, &key, BPF_ANY);
#ifdef ENABLE_DEBUG
			if (ret != 0) {
				bpf_printk("[BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB] servers push failed: %d", ret);
			} else {
				bpf_printk("[BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB] servers push");
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
	bpf_printk("[sk_skb_stream_parser_prog] local [%u.%u.%u.%u:%u], remote [%u.%u.%u.%u:%u]",
		FORMAT_IP(skb->local_ip4), skb->local_port,
		FORMAT_IP(skb->remote_ip4), bpf_ntohl(skb->remote_port));
#endif
	return skb->len;
}

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

SEC("sk_skb/stream_verdict/prog")
int sk_skb_stream_verdict_prog(struct __sk_buff *skb)
{
#ifdef ENABLE_DEBUG
	bpf_printk("[sk_skb_stream_verdict_prog] local [%u.%u.%u.%u:%u], remote [%u.%u.%u.%u:%u], len [%u], data len [%u]",
		FORMAT_IP(skb->local_ip4), skb->local_port,
		FORMAT_IP(skb->remote_ip4), bpf_ntohl(skb->remote_port), skb->len, skb->data_end - skb->data);
#endif

	struct socket_4_tuple key = {
		.local_ip4 = skb->local_ip4,
		.local_port = skb->local_port,
		.remote_ip4 = skb->remote_ip4,
		.remote_port = skb->remote_port,
	};

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
	bpf_printk("[sk_skb_stream_verdict_prog] code=[%u], len=[%d]", *code, *len);
#endif

#ifdef ENABLE_FAST_REDIRECT
	int ret;

	if (skb->local_port == POOLER_PORT) {
		if ((*code) == 'Q') {
			// SimpleQuery, select a server from servers and redirect
			struct socket_4_tuple server_key;
			ret = bpf_map_pop_elem(&servers, &server_key);
			if (ret != 0) {
#ifdef ENABLE_DEBUG
				bpf_printk("[sk_skb_stream_verdict_prog] servers pop failed: %d", ret);
#endif
				return fallback_redirect(skb, &key);
			}
#ifdef ENABLE_DEBUG
			bpf_printk("[sk_skb_stream_verdict_prog] servers pop");
#endif

			ret = bpf_map_update_elem(&pairs, &server_key, &key, BPF_ANY);
			if (ret != 0) {
#ifdef ENABLE_DEBUG
				bpf_printk("[sk_skb_stream_verdict_prog] pairs update failed: %d", ret);
#endif
				return fallback_redirect(skb, &key);
			}
#ifdef ENABLE_DEBUG
			bpf_printk("[sk_skb_stream_verdict_prog] pairs update");
#endif

			ret = bpf_sk_redirect_hash(skb, &sockmap, &server_key, 0);
			if (ret == 0) {
#ifdef ENABLE_DEBUG
				bpf_printk("[sk_skb_stream_verdict_prog] sockmap redirect to server failed");
#endif
				return fallback_redirect(skb, &key);
			}
#ifdef ENABLE_DEBUG
			bpf_printk("[sk_skb_stream_verdict_prog] sockmap redirect to server");
#endif
			return ret;
		}
	} else if (bpf_ntohl(skb->remote_port) == BACKEND_PORT) {
		if ((*code) == 'T' || (*code) == 'I' || (*code) == 'C') {
			// T: RowDescription, push server back to servers, and redirect
			// I: EmptyQueryResponse, push server back to servers, and redirect
			// C: CommandComplete, push server back to servers, and redirect
			struct socket_4_tuple* client_key;
			client_key = bpf_map_lookup_elem(&pairs, &key);
			if (client_key == NULL) {
#ifdef ENABLE_DEBUG
				bpf_printk("[sk_skb_stream_verdict_prog] pairs lookup failed");
#endif
				return fallback_redirect(skb, &key);
			}
#ifdef ENABLE_DEBUG
			bpf_printk("[sk_skb_stream_verdict_prog] pairs lookup");
#endif

			ret = bpf_map_push_elem(&servers, &key, BPF_ANY);
			if (ret != 0) {
#ifdef ENABLE_DEBUG
				bpf_printk("[sk_skb_stream_verdict_prog] servers push failed: %d", ret);
#endif
				return fallback_redirect(skb, &key);
			}
#ifdef ENABLE_DEBUG
			bpf_printk("[sk_skb_stream_verdict_prog] servers push");
#endif

			ret = bpf_sk_redirect_hash(skb, &sockmap, client_key, 0);
			if (ret == 0) {
#ifdef ENABLE_DEBUG
				bpf_printk("[sk_skb_stream_verdict_prog] sockmap redirect to client failed");
#endif
				return fallback_redirect(skb, &key);
			}
#ifdef ENABLE_DEBUG
			bpf_printk("[sk_skb_stream_verdict_prog] sockmap redirect to client");
#endif
			return ret;
		}
	}
#endif

	return fallback_redirect(skb, &key);
}

char _license[] SEC("license") = "GPL";
