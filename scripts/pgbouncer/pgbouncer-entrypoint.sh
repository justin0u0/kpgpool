#!/bin/bash

echo "Running pgbouncer-entrypoint.sh script"

if [ -n "$ENABLE_BPF" ]; then
	if [ "$BPF_LOAD_PAIRS" = "true" ]; then
		echo "bpfpgpool bpf load --load-pairs"
		bpfpgpool bpf load --load-pairs &
	else
		echo "bpfpgpool bpf load"
		bpfpgpool bpf load &
	fi
	sleep 2
fi

if [ -n "$ENABLE_TSHARK" ]; then
	echo "tshark -i any -f 'host 10.121.240.151 or host 10.121.240.152' -w /tmp/out.pcapng"
	tshark -i any -f 'host 10.121.240.151 or host 10.121.240.152' -w /tmp/out.pcapng &
	sleep 2
fi
