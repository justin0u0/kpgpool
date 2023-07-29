all: bpf/*.o build

bpf/*.o: bpf/*.c
	go generate ./bpf/...

.PHONY: build
build:
	go build -o bin/bpfpgpool ./cmd/...

.PHONY: up
up:
	docker-compose up -d --build --force-recreate

.PHONY: exec
exec:
	docker-compose exec -it bpfpgpool bash

.PHONY: clean
clean:
	rm -rf bin
