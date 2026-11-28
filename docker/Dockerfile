# Wardenlens image (#69, ADR 0003/0004/0005/0006). Build from the repository root:
#   docker build -f docker/Dockerfile -t wardenlens:local .
# Every base image is pinned by digest (scripts/tests/docker.test.sh checks it). To update a pin, resolve the new
# tag with `docker buildx imagetools inspect <image:tag>`, review the change, and edit the digest below.

# Builder: Rust toolchain of rust-toolchain.toml (1.100.0; rustup honours the copied file), a C compiler for
# rusqlite `bundled` (gcc and libc headers come with the slim image).
FROM rust:1.100.0-slim-bookworm@sha256:bb875b0f8ce726053e259034848c471840e96bfe591fd52556178ae9a05e6126 AS builder
WORKDIR /src
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates ./crates
# The vendored, patched retina of [patch.crates-io] (ADR 0002 section 13, #155); the build fails without it.
COPY third_party ./third_party
# The camera catalogue is embedded in the CLI with include_str! (#67).
COPY cameras ./cameras
RUN cargo build --release --locked -p wardenlens-cli

# Test executables of the crate that uses openat2 / renameat2 (ADR 0005 section 11), built here and run by
# `scripts/docker-selftest` in the runtime image, under the container runtime's seccomp profile.
FROM builder AS fsutil-tests-build
RUN mkdir /out \
 && cargo test --release --locked -p wardenlens-fsutil --no-run 2>&1 \
  | sed -n 's/^ *Executable .*(\(target\/[^)]*\))$/\1/p' \
  | while read -r exe; do cp "$exe" /out/; done \
 && test -n "$(ls /out)"

# Runtime base: the CUDA base image (ADR 0003), CA certificates only, a fixed non-root uid.
# The recording volumes and /var/lib/wardenlens must be owned by this uid on the host (docs/deploy.md).
FROM nvidia/cuda:12.9.1-base-ubuntu24.04@sha256:29e5e3425e2e0f5a4e97c9fb4695ba4887cd78210a43cf94c3bcafc6ab01c5e6 AS base
ENV NVIDIA_DRIVER_CAPABILITIES=compute,video,utility
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 wardenlens \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin wardenlens

# Self-test image (not the default target): the fsutil tests. The default user is the service uid; scripts/docker-selftest
# overrides it with the host uid (--user) so the bind-mounted temporary directory is writable.
FROM base AS selftest
COPY --from=fsutil-tests-build /out/ /selftest/
USER 10001:10001

# The service image (the default target, last stage). The entrypoint checks the key file, then serves.
FROM base AS runtime
COPY --from=builder /src/target/release/wardenlens /usr/local/bin/wardenlens
COPY docker/entrypoint.sh /usr/local/bin/wardenlens-entrypoint
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/wardenlens-entrypoint"]
CMD ["serve"]
