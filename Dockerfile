FROM rust:1.91-alpine AS build
WORKDIR /src

RUN apk add --no-cache build-base

COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release

FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=build /src/target/release/bns /app/bns
COPY web /app/web
COPY config.example.yaml /app/config.example.yaml

ENV BNS_CONFIG=/config/config.yaml

EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 8080/tcp

ENTRYPOINT ["/app/bns"]
