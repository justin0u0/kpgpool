all: bpf/*.o build

bpf/*.o: bpf/*.c
	go generate ./bpf/...

.PHONY: build
build:
	go build -o bin/kpgpool ./cmd/...

.PHONY: up
up:
	docker-compose up -d --build --force-recreate

.PHONY: exec
exec:
	docker-compose exec -it kpgpool bash

.PHONY: clean
clean:
	rm -rf bin
