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
#define TX_MODE
#define SUPPORT_PREPARED_STATEMENT
#define POSTGRES_MAX_IDENTIFIER_LENGTH 64
#define POSTGRES_MAX_MESSAGES 1024
#define POSTGRES_MAX_MESSAGE_SIZE 32768
// #define ENABLE_DEBUG

#define unlikely(x) __builtin_expect(!!(x), 0)

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

#define FNV32_PRIME 16777619
#define FNV32_OFFSET 2166136261U

struct pgmsghdr {
	u8 code;
	u32 len;
} __attribute__((__packed__));

struct socket_4_tuple {
	u32 local_ip4;		// network byte order
	u32 local_port;		// host byte order
	u32 remote_ip4;		// network byte order
	u32 remote_port;	// network byte order
};

struct client_state {
	// valid indicates whether the server is valid.
	u8 valid;
	// server is the current server the client is connected to.
	struct socket_4_tuple server;
};

struct server_state {
	// valid indicates whether the client is valid.
	u8 valid;
	// client is the client the server is connected to.
	struct socket_4_tuple client;
	// prepared maps the hash prepared statement into the prepared statement name.
	u8 prepared[256][POSTGRES_MAX_IDENTIFIER_LENGTH];
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 2000);
	__type(key, struct socket_4_tuple);
	__type(value, u32); // socket FD
} sockhash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 1000);
	__type(value, struct socket_4_tuple);
} servers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, struct socket_4_tuple);
	__type(value, struct client_state);
} client_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, struct socket_4_tuple);
	__type(value, struct server_state);
} server_states SEC(".maps");

u8 is_unprepared_statement(struct __sk_buff* skb, struct server_state* ss) {
	void* data = (void*)(long)skb->data;
	void* data_end = (void*)(long)skb->data_end;

	if (!ss) {
		return 0;
	}

	u32 offset = 0;
	for (int messages = 0; messages < POSTGRES_MAX_MESSAGES; ++messages) {
		if (unlikely(offset > POSTGRES_MAX_MESSAGE_SIZE)) {
			return 0;
		}
		if (unlikely(offset >= skb->len)) {
			return 0;
		}

		struct pgmsghdr* pgh = data + offset;
		if (unlikely((void*)(pgh + 1) > data_end)) {
			return 0;
		}

		// Parse must go to user-space.
		if (pgh->code == 'P') {
			return 1;
		}

		// Bind must go to user-space if the server is not prepared.
		if (pgh->code == 'B') {
			u8* ns = data + offset + 6;
			u8* ne = ns;
			u32 hash = FNV32_OFFSET;
			for (int i = 0; i < POSTGRES_MAX_IDENTIFIER_LENGTH; ++i) {
				if (unlikely((void*)(ne) + 1 > data_end)) {
					return 0;
				}
				if (*ne == '\0') {
					break;
				}
				hash ^= (u32)(*ne);
				hash *= FNV32_PRIME;
				++ne;
			}
			hash &= 0xFF;

			ne = ns;
			for (int i = 0; i < POSTGRES_MAX_IDENTIFIER_LENGTH; ++i) {
				if (unlikely((void*)(ne) + 1 > data_end)) {
					return 0;
				}
				if (*ne == '\0') {
					break;
				}
				if (*ne != ss->prepared[hash][i]) {
					return 1;
				}
				++ne;
			}

			return 0;
		}

		offset += bpf_ntohl(pgh->len) + 1;
	}

	return 0;
}

u8 is_ready_for_query_idle(struct __sk_buff* skb) {
	void* data = (void*)(long)skb->data;
	void* data_end = (void*)(long)skb->data_end;

	u32 offset = 0;
	for (int messages = 0; messages < POSTGRES_MAX_MESSAGES; ++messages) {
		if (unlikely(offset > POSTGRES_MAX_MESSAGE_SIZE)) {
			return 0;
		}
		if (unlikely(offset >= skb->len)) {
			return 0;
		}

		struct pgmsghdr* pgh = data + offset;
		if (unlikely((void*)(pgh + 1) > data_end)) {
			return 0;
		}

		if (pgh->code == 'Z') {
			u8* status = (u8*)(pgh + 1);
			if (unlikely((void*)(status + 1) > data_end)) {
				return 0;
			}
			if (*status == 'I') {
				return 1;
			}
		}

		offset += bpf_ntohl(pgh->len) + 1;
	}

	return 0;
}

SEC("sk_skb/stream_verdict/prog/pool")
int sk_skb_stream_verdict_prog_pool(struct __sk_buff* skb)
{
#ifdef ENABLE_DEBUG
	bpf_printk("[sk_skb_stream_verdict_prog_pool] %u.%u.%u.%u:%u->%u.%u.%u.%u:%u",
		FORMAT_IP(skb->local_ip4), skb->local_port,
		FORMAT_IP(skb->remote_ip4), bpf_ntohl(skb->remote_port));
	bpf_printk("[sk_skb_stream_verdict_prog_pool] raw %u %u %u %u",
		skb->local_ip4, skb->local_port,
		skb->remote_ip4, skb->remote_port);
#endif

	struct socket_4_tuple key = {
		.local_ip4 = skb->local_ip4,
		.local_port = skb->local_port,
		.remote_ip4 = skb->remote_ip4,
		.remote_port = skb->remote_port,
	};

	if (skb->local_port == POOLER_PORT) { // client packet
		struct client_state* cs = bpf_map_lookup_elem(&client_states, &key);
		if (unlikely(!cs)) {
			bpf_printk("[sk_skb_stream_verdict_prog_pool] no client state");
			return SK_PASS;
		}

		struct server_state* ss;

		if (!cs->valid) {
			struct socket_4_tuple server;
			if (unlikely(bpf_map_pop_elem(&servers, &server) != 0)) {
				bpf_printk("[sk_skb_stream_verdict_prog_pool] no server");
				return SK_PASS;
			}

			cs->valid = 1;
			cs->server = server;

	#ifdef ENABLE_DEBUG
			bpf_printk("[sk_skb_stream_verdict_prog_pool] got server %u.%u.%u.%u:%u->%u.%u.%u.%u:%u",
				FORMAT_IP(server.local_ip4), server.local_port,
				FORMAT_IP(server.remote_ip4), bpf_ntohl(server.remote_port));
			bpf_printk("[sk_skb_stream_verdict_prog_pool] got server (raw) %u %u %u %u",
				server.local_ip4, server.local_port, server.remote_ip4, server.remote_port);
	#endif

			ss = bpf_map_lookup_elem(&server_states, &server);
			if (unlikely(!ss)) {
				bpf_printk("[sk_skb_stream_verdict_prog_pool] no server state");
				return SK_PASS;
			}
			ss->valid = 1;
			ss->client = key;
		} else {
#ifdef SUPPORT_PREPARED_STATEMENT
			ss = bpf_map_lookup_elem(&server_states, &cs->server);
#endif
		}

#ifdef SUPPORT_PREPARED_STATEMENT
		if (is_unprepared_statement(skb, ss)) {
			return SK_PASS;
		}
#endif // SUPPORT_PREPARED_STATEMENT

		return bpf_sk_redirect_hash(skb, &sockhash, &cs->server, 0);
	}

	if (bpf_ntohl(skb->remote_port) == BACKEND_PORT) { // server packet
		struct server_state* ss = bpf_map_lookup_elem(&server_states, &key);
		if (unlikely(!ss)) {
			bpf_printk("[sk_skb_stream_verdict_prog_pool] no server state");
			return SK_PASS;
		}
		if (unlikely(!ss->valid)) {
			bpf_printk("[sk_skb_stream_verdict_prog_pool] no valid client binding to the server");
			return SK_PASS;
		}

#ifdef TX_MODE
		if (is_ready_for_query_idle(skb)) {
#ifdef ENABLE_DEBUG
			bpf_printk("[sk_skb_stream_verdict_prog_pool] transaction status: idle");
#endif

			// remove the server->client binding
			ss->valid = 0;

			// remove the client->server binding
			struct client_state* cs = bpf_map_lookup_elem(&client_states, &ss->client);
			if (unlikely(!cs)) {
				bpf_printk("[sk_skb_stream_verdict_prog_pool] no client state");
			} else {
				cs->valid = 0;
			}

			// put the server back to the pool
			bpf_map_push_elem(&servers, &key, BPF_ANY);
		}
#endif // TX_MODE

		return bpf_sk_redirect_hash(skb, &sockhash, &ss->client, 0);
	}

	bpf_printk("[sk_skb_stream_verdict_prog_pool] non-targetted packet");

	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
