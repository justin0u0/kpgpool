#!/bin/bash

if [ -n "$ENABLE_BPF" ]; then
	bpfpgpool bpf load &
	sleep 2
fi

if [ -n "$ENABLE_TSHARK" ]; then
	tshark -i any -c 1000 -w /tmp/out.pcapng &
	sleep 2
fi

pgbouncer -v -d /etc/pgbouncer/pgbouncer.ini

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?
