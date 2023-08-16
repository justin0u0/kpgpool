FROM bitnami/pgbouncer:1.19.1 AS bpfpgpool-pgbouncer

USER root

RUN apt-get update && apt-get install -y bpftool iproute2 lsof tshark

COPY bin/bpfpgpool /usr/local/bin/bpfpgpool

FROM ghcr.io/postgresml/pgcat AS bpfpgpool-pgcat

USER root

RUN apt-get update && apt-get install -y bpftool iproute2 lsof tshark

COPY bin/bpfpgpool /usr/local/bin/bpfpgpool
COPY scripts/pgcat-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

CMD ["/usr/local/bin/docker-entrypoint.sh"]

FROM golang:1.19 AS bpfpgpool-pgclient

COPY bin/bpfpgpool /usr/local/bin/bpfpgpool

CMD ["bpfpgpool", "pg", "loop-query", "-u", "host=10.121.240.150 port=6432 user=postgres password=password dbname=postgres sslmode=disable connect_timeout=5", "-c", "1"]
