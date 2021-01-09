FROM rust:1.48.0 as build
ENV PKG_CONFIG_ALLOW_CROSS=1

WORKDIR /usr/src/atomic-data
COPY . .

RUN cargo install --bin=atomic-server --path server
# Minimal image, but with OpenSSL support
FROM gcr.io/distroless/cc-debian10

# Copy compiled executable
COPY --from=build /usr/local/cargo/bin/atomic-server /usr/local/bin/atomic-server
# Copy static files, tera templates & default store
WORKDIR /usr/src/atomic-data
COPY ./server/ ./server
WORKDIR /usr/src/atomic-data/server
CMD ["atomic-server"]
