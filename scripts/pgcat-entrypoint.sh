#!/bin/bash

if [ -n "$ENABLE_BPF" ]; then
	bpfpgpool bpf load &
	sleep 1
fi

if [ -n "$ENABLE_TSHARK" ]; then
	tshark -i eth0 -w /tmp/out.pcapng &
	sleep 1
fi

pgcat /etc/pgcat/pgcat.toml &

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?
