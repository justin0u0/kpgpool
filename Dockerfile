FROM bitnami/pgbouncer:1.18.0 AS bpfpgpool

USER root

COPY bin/bpfpgpool /usr/local/bin/bpfpgpool

FROM bpfpgpool AS bpfpgpool-debug

RUN apt-get update && apt-get install -y bpftool iproute2 lsof
