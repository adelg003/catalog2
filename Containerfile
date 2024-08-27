#################
## Build Image ##
#################
FROM rust:alpine as builder

# Setup dependencies
RUN apk add musl-dev npm

# Copy files to build Rust Application
WORKDIR /opt/catalog2
COPY ./build.rs ./build.rs
COPY ./Cargo.* .
COPY ./migrations ./migrations
COPY ./package.json ./package.json
COPY ./package-lock.json ./package-lock.json
COPY ./password_hasher ./password_hasher
COPY ./.sqlx ./.sqlx
COPY ./src ./src
COPY ./templates ./templates

# Build Rust Application
RUN SQLX_OFFLINE=true cargo build --release --locked

###################
## Runtime Image ##
###################
FROM alpine:latest

# Copy over complied runtime binary
COPY --from=builder /opt/catalog2/target/release/catalog2 /usr/local/bin/catalog2

# Run Catalog2
ENV RUST_BACKTRACE=full
ENTRYPOINT ["catalog2"]
