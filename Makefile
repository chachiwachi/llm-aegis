WASM_SRC := engine/target/wasm32-unknown-unknown/release/aegis_engine.wasm
WASM_DST := internal/engine/aegis_engine.wasm
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all engine build test test-engine test-go lint docker clean

all: build

engine:
	cd engine && cargo build --release --target wasm32-unknown-unknown
	cp $(WASM_SRC) $(WASM_DST)

build: engine
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/aegis ./cmd/aegis

test: test-engine test-go

test-engine:
	cd engine && cargo test

test-go: engine
	go test -race ./...

lint:
	cd engine && cargo fmt --check && cargo clippy --all-targets -- -D warnings
	go vet ./...

docker:
	docker build -t llm-aegis:$(VERSION) .

clean:
	rm -rf bin $(WASM_DST)
	cd engine && cargo clean
