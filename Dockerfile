FROM rust:latest as builder
WORKDIR /usr/src/app
COPY Cargo.toml .
COPY src ./src
RUN cargo install --path .

FROM debian:latest
COPY --from=builder /usr/local/cargo/bin/tda-daemon /usr/local/bin/tda-daemon

EXPOSE 13434

CMD ["tda-daemon"]
