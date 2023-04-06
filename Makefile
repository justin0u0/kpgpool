all: bpfgo/bpf/*.o build

bpfgo/bpf/*.o: bpfgo/bpf/*.c
	go generate ./bpfgo/...

.PHONY: build
build:
	go build -o bin/bpfpgpool ./cmd/...

.PHONY: up
up:
	docker-compose up -d --build

.PHONY: exec
exec:
	docker-compose exec -it bpfpgpool bash

.PHONY: clean
clean:
	rm -rf bin
