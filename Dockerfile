FROM bitnami/pgbouncer:1.20.1 AS bpfpgpool-pgbouncer

USER root

RUN apt-get update && apt-get install -y bpftool iproute2 lsof tshark

COPY bin/bpfpgpool /usr/local/bin/bpfpgpool
# COPY scripts/pgbouncer-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# CMD ["/usr/local/bin/docker-entrypoint.sh"]

# latest
FROM ghcr.io/postgresml/pgcat AS bpfpgpool-pgcat

# v1.1.1
# FROM ghcr.io/postgresml/pgcat:1f2c6507f7fb5461df1a599c0b380aa114597bb5 AS bpfpgpool-pgcat

# v1.0.0
# FROM ghcr.io/postgresml/pgcat:0d5feac4b299ab9eac8cdb6641d06b0606696442 AS bpfpgpool-pgcat

USER root

RUN apt-get update && apt-get install -y bpftool iproute2 lsof tshark postgresql-client

COPY bin/bpfpgpool /usr/local/bin/bpfpgpool
COPY scripts/pgcat-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

CMD ["/usr/local/bin/docker-entrypoint.sh"]

FROM golang:1.19 AS bpfpgpool-pgclient

COPY bin/bpfpgpool /usr/local/bin/bpfpgpool

CMD ["bpfpgpool", "pg", "loop-query", "-u", "host=10.121.240.150 port=6432 user=bpfpgpool password=bpfpgpool dbname=bpfpgpool sslmode=disable connect_timeout=5", "-c", "1"]
