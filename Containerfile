# Build image
FROM rust:latest as builder

# Setup Node
RUN apt update
RUN apt install --yes npm

# Copy files to build Rust Application
WORKDIR /usr/src/myapp
COPY ./build.rs ./build.rs
COPY ./Cargo.* .
COPY ./migrations ./migrations
COPY ./package.json ./package.json
COPY ./password_hasher ./password_hasher
COPY ./.sqlx ./.sqlx
COPY ./src ./src
COPY ./templates ./templates

# Build Rust Application
RUN SQLX_OFFLINE=true cargo install --path .

# Copy compiled binary to runtime image
FROM debian:latest
WORKDIR /opt/catalog2
COPY --from=builder /usr/local/cargo/bin/catalog2 /usr/local/bin/catalog2
ENV RUST_BACKTRACE=full
ENTRYPOINT ["catalog2"]
