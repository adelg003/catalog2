#################
## Build Image ##
#################
FROM rust:alpine as builder

# Setup dependencies
RUN apk add --no-cache musl-dev npm

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
FROM alpine:3

# Setup dependencies
RUN apk add --no-cache alpine-conf curl

# Setup Catalog2 User
RUN setup-user catalog2
USER catalog2
WORKDIR /home/catalog2

# Copy over complied runtime binary
COPY --from=builder /opt/catalog2/target/release/catalog2 /usr/local/bin/catalog2

# Setup Healthcheck
HEALTHCHECK CMD curl --fail http://localhost:3000

# Run Catalog2
ENV RUST_BACKTRACE=full
ENTRYPOINT ["catalog2"]
