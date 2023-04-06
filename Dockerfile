FROM golang:1.19 AS kpgpool-pool

COPY bin/kpgpool /usr/local/bin/kpgpool

CMD ["kpgpool", "pool"]
