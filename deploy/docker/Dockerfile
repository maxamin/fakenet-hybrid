# FakeNet hybrid in one container: the Camel daemon and the Rust nucleus, which talk over
# loopback, run side by side. Point traffic at the container's published service ports; the
# daemon decides replies from routes/ (bind-mount your own to edit them live). Diversion is
# NOT used in a container (no host network takeover); this serves the fake services directly.
#
#   docker build -f deploy/docker/Dockerfile -t fakenet-hybrid .
#   docker run --rm -p 8080:8080 -p 53:53/udp -v "$PWD/daemon/routes:/opt/fakenet/routes" fakenet-hybrid
#
# Lab use only. The control, health and link interfaces stay on loopback inside the
# container; only the fake service ports are published.

# --- Build the nucleus ---
FROM rust:1.83-slim-bookworm AS nucleus
WORKDIR /src
COPY nucleus/ ./nucleus/
COPY schema/ ./schema/
RUN cd nucleus && cargo build --release -p fakenet-cli && strip target/release/fakenet-nucleus

# --- Build the daemon ---
FROM maven:3.9-eclipse-temurin-21 AS daemon
WORKDIR /src
COPY daemon/pom.xml ./daemon/pom.xml
# Warm the dependency cache on the pom alone, so code changes don't re-download Camel
RUN cd daemon && mvn -q -B -Dmaven.test.skip=true dependency:go-offline
COPY daemon/ ./daemon/
RUN cd daemon && mvn -q -B -Dmaven.test.skip=true package

# --- Runtime ---
FROM eclipse-temurin:21-jre-noble
RUN useradd --system --uid 10001 --home /opt/fakenet --shell /usr/sbin/nologin fakenet
WORKDIR /opt/fakenet
COPY --from=nucleus /src/nucleus/target/release/fakenet-nucleus /usr/local/bin/fakenet-nucleus
COPY --from=daemon /src/daemon/target/fakenet-daemon.jar ./daemon/fakenet-daemon.jar
COPY --from=daemon /src/daemon/target/lib ./daemon/lib
COPY daemon/routes ./routes
COPY nucleus/config/default-files ./config/default-files
COPY deploy/docker/fakenet.container.toml ./config/fakenet.toml
COPY deploy/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN mkdir -p capture audit && chown -R fakenet:fakenet /opt/fakenet && chmod +x /usr/local/bin/entrypoint.sh
USER fakenet
# The health endpoint (loopback): the container is healthy once the nucleus serves it
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s \
  CMD ["/bin/sh","-c","exec 3<>/dev/tcp/127.0.0.1/8099 && printf 'GET /health HTTP/1.0\\r\\n\\r\\n' >&3 && head -1 <&3 | grep -q 200"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
