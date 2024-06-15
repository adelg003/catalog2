# Compile image
FROM rust:latest as builder
WORKDIR /usr/src/myapp
COPY ./Cargo.* .
COPY ./src ./src
COPY ./migrations ./migrations
COPY ./.sqlx ./.sqlx
COPY ./password_hasher ./password_hasher
RUN SQLX_OFFLINE=true cargo install --path .

# Copy compiled binary to runtime image
FROM debian:latest
WORKDIR /opt/catalog2
COPY --from=builder /usr/local/cargo/bin/catalog2 /usr/local/bin/catalog2
ENV RUST_BACKTRACE=full
ENTRYPOINT ["catalog2"]
