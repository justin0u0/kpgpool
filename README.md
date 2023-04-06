# kpgpool

A BPF based PostgreSQL connection pool.

## Usage

Prerequisites:
- Linux kernel version >= 6.1.0
- Go version >= 1.19
- Docker

### Build

```bash
make build
```

### Run

```bash
docker compose up -d --build --force-recreate kpgpool-bpf-pool kpgpool-pool kpgpool-pgbouncer
```

### Evaluate

Note: add `-b` to setup the database for the first time.

Simple query protocol:

```bash
./bin/bpfpgpool client bench -c 8 -q 1 -d 10s -u "postgres://postgres:postgres@10.140.0.11:6432/postgres?sslmode=disable&default_query_exec_mode=simple_protocol"
```

Extended query protocol:

```bash
./bin/bpfpgpool client bench -c 8 -q 1 -d 10s -u "postgres://postgres:postgres@10.140.0.11:6432/postgres?sslmode=disable"
```
