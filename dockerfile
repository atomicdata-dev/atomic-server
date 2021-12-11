FROM rust as planner

WORKDIR /app
RUN cargo install cargo-chef
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM rust  as cacher
WORKDIR /app
RUN cargo install cargo-chef
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM rust  as builder
WORKDIR /app
COPY . .
# Copy over the cached dependencies
COPY --from=cacher /app/target target
COPY --from=cacher $CARGO_HOME $CARGO_HOME
RUN cargo build --release --bin atomic-server

# We only need a small runtime for this step, but make sure glibc is installed
FROM frolvlad/alpine-glibc as runtime

COPY ./server/ /server
WORKDIR /server
COPY --from=builder /app/target/release/atomic-server /server/atomic-server-bin
ENV ATOMIC_STORE_PATH="/atomic-storage/db"
ENV ATOMIC_CONFIG_PATH="/atomic-storage/config.toml"
ENV ATOMIC_PORT="80"
ENV ATOMIC_PORT_HTTPS="433"
ENTRYPOINT ["/server/atomic-server-bin"]
