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
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 65536);
	__type(key, u32);		// pooler port
	__type(value, u32); // socket FD
} p2sSockmap SEC(".maps"); // pooler to server sockets

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 65536);
	__type(key, u32);		// client port
	__type(value, u32); // socket FD
} c2pSockmap SEC(".maps"); // client to pooler sockets

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);		// pooler port between pooler and server
	__type(value, u32); // client port
} p2c SEC(".maps"); // pooler to server bindings

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);		// client port
	__type(value, u32); // pooler port between pooler and server
} c2p SEC(".maps"); // client to pooler bindings

SEC("sockops/prog")
int sockops_prog(struct bpf_sock_ops *skops) {
	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // SYN-ACK
		if (skops->local_port == POOLER_PORT) {
#ifdef ENABLE_DEBUG
			bpf_printk("[BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB] local [%u.%u.%u.%u:%u], remote [%u.%u.%u.%u:%u]",
				FORMAT_IP(skops->local_ip4), skops->local_port,
				FORMAT_IP(skops->remote_ip4), bpf_ntohl(skops->remote_port));
			/*
			bpf_printk("[BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB] raw %x %x %x %x",
				skops->local_ip4, skops->local_port,
				skops->remote_ip4, skops->remote_port);
			*/
#endif

			/*
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
			*/
		}
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: // SYN
		if (bpf_ntohl(skops->remote_port) == BACKEND_PORT) {
#ifdef ENABLE_DEBUG
			bpf_printk("[BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB] local [%u.%u.%u.%u:%u], remote [%u.%u.%u.%u:%u]",
				FORMAT_IP(skops->local_ip4), skops->local_port,
				FORMAT_IP(skops->remote_ip4), bpf_ntohl(skops->remote_port));
			/*
			bpf_printk("[BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB] raw %x %x %x %x",
				skops->local_ip4, skops->local_port,
				skops->remote_ip4, skops->remote_port);
			*/
#endif

			/*
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
			*/
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

	/*
	struct socket_4_tuple key = {
		.local_ip4 = skb->local_ip4,
		.local_port = skb->local_port,
		.remote_ip4 = skb->remote_ip4,
		.remote_port = skb->remote_port,
	};
	return bpf_sk_redirect_hash(skb, &sockmap, &key, BPF_F_INGRESS);

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

	u32 key;
	u32* val;
	if (skb->local_port == POOLER_PORT) {
		key = bpf_ntohl(skb->remote_port); // client port
		val = bpf_map_lookup_elem(&c2p, &key); // pooler port between pooler and server
		if (!val) {
			bpf_printk("[sk_skb_stream_verdict_prog] no pooler found for client port [%u]", key);
			return SK_DROP;
		}
		bpf_printk("[sk_skb_stream_verdict_prog] redirect client packet to server with pooler port [%u]", *val);
		return bpf_sk_redirect_map(skb, &p2sSockmap, *val, 0);
	} else if (bpf_ntohl(skb->remote_port) == BACKEND_PORT) {
		key = skb->local_port; // pooler port between pooler and server
		val = bpf_map_lookup_elem(&p2c, &key); // client port
		if (!val) {
			bpf_printk("[sk_skb_stream_verdict_prog] no client found for pooler port [%u]", key);
			return SK_DROP;
		}
		bpf_printk("[sk_skb_stream_verdict_prog] redirect server packet to client with client port [%u]", *val);
		return bpf_sk_redirect_map(skb, &c2pSockmap, *val, 0);
	}

	bpf_printk("[sk_skb_stream_verdict_prog] non-targetted packet");
	return SK_DROP;
}

char _license[] SEC("license") = "GPL";
