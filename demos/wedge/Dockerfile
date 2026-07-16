# The M8 wedge demo image — builds both binaries (merchant + agent) from the RI
# tree. Build context is the paytp-ri repo root (see docker-compose.yml) so the
# demo's `../../crates/*` path deps and the workspace root `Cargo.toml` (needed
# to resolve the crates' `workspace = true` deps) are both present.
FROM rust:1-slim AS build
# The RI crates are pure-Rust (RustCrypto, no ring/openssl), but keep a C
# toolchain available so any transitive build script that wants `cc` succeeds.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Only what the standalone demo workspace needs to compile.
COPY Cargo.toml ./Cargo.toml
COPY crates ./crates
COPY demos/wedge ./demos/wedge
WORKDIR /src/demos/wedge
RUN cargo build --release --bins

FROM debian:bookworm-slim
COPY --from=build /src/demos/wedge/target/release/wedge-merchant /usr/local/bin/wedge-merchant
COPY --from=build /src/demos/wedge/target/release/wedge-agent /usr/local/bin/wedge-agent
COPY --from=build /src/demos/wedge/target/release/wedge-channel /usr/local/bin/wedge-channel
ENV WEDGE_ADDR=0.0.0.0:8402
EXPOSE 8402
CMD ["wedge-merchant"]
