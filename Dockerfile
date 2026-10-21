# ── Stage 1: build ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ make python3 libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Build Botan 3.14.0 from vendored source.
# This layer is cached until botan-src/ changes, so normal code iterations are fast.
COPY botan-src/ botan-src/
RUN cd botan-src && \
    python3 configure.py --prefix=/usr/local && \
    make -j"$(nproc)" && \
    make install

# Copy application source after Botan so code changes don't invalidate the Botan layer.
COPY Makefile .
COPY common/ common/
COPY server/ server/
COPY client/ client/

# Build server and client against the system-installed Botan.
RUN make all \
    CXX=g++ \
    CXXFLAGS="-std=c++20 -I/usr/local/include/botan-3 -I. -Wall -pthread" \
    LDFLAGS="-L/usr/local/lib -lbotan-3 -Wl,-rpath,/usr/local/lib -lpthread -lsqlite3"

# ── Stage 2: runtime ───────────────────────────────────────────────────────────
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="ZeroTraceMsg" \
      org.opencontainers.image.description="Post-quantum end-to-end encrypted messaging server" \
      org.opencontainers.image.url="https://github.com/ahmedmoabdeldayem/ZeroTraceMsg" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# Non-root service account
RUN useradd --system --no-create-home --shell /usr/sbin/nologin zerotrace

# Botan shared library. The versioned file is the real artifact;
# ldconfig regenerates the SONAME symlink (libbotan-3.so.3) automatically.
COPY --from=builder /usr/local/lib/libbotan-3.so.3.14.0 /usr/local/lib/
RUN ldconfig

# Application binaries
COPY --from=builder /src/build/msg_server /usr/local/bin/msg_server
COPY --from=builder /src/build/msg_client /usr/local/bin/msg_client

# Persistent state: SQLite database + auto-generated TLS certs
RUN install -d -o zerotrace -g zerotrace \
    /var/lib/zerotrace \
    /var/lib/zerotrace/certs \
    /etc/zerotrace

COPY deploy/zerotrace.conf.docker /etc/zerotrace/zerotrace.conf

WORKDIR /var/lib/zerotrace
EXPOSE 9999

# TCP liveness probe — confirms the port is accepting connections.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD bash -c 'echo > /dev/tcp/localhost/9999' 2>/dev/null || exit 1

USER zerotrace

# Pass a custom config path as the first argument to override the default.
# Example: docker run zerotracemsg /run/secrets/zerotrace.conf
ENTRYPOINT ["/usr/local/bin/msg_server"]
CMD ["/etc/zerotrace/zerotrace.conf"]
