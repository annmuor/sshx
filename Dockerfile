FROM rust:alpine3.18 as builder

RUN apk add --no-cache musl-dev
RUN mkdir /app
COPY src/ app/src
COPY deps/ app/deps
COPY Cargo.toml app/Cargo.toml
WORKDIR /app
RUN cargo build -r

FROM alpine:3.18
EXPOSE 2222
RUN apk add --no-cache bash
COPY entry.sh /entry.sh
COPY --from=builder /app/target/release/sshx /usr/bin/sshx
RUN chmod 755 /entry.sh
ENTRYPOINT /entry.sh
