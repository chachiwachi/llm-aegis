# 1) Motor de detección: Rust -> WebAssembly
FROM rust:1-slim AS engine
RUN rustup target add wasm32-unknown-unknown
WORKDIR /src/engine
COPY engine/ .
RUN cargo build --release --target wasm32-unknown-unknown

# 2) Gateway: Go con el WASM incrustado (sin cgo)
FROM golang:1-alpine AS gateway
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=engine /src/engine/target/wasm32-unknown-unknown/release/aegis_engine.wasm internal/engine/aegis_engine.wasm
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/aegis ./cmd/aegis

# 3) Imagen final mínima, sin shell y sin root
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=gateway /out/aegis /aegis
COPY aegis.example.yaml /etc/aegis/aegis.yaml
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/aegis"]
CMD ["serve", "-config", "/etc/aegis/aegis.yaml"]
