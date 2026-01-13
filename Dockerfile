# syntax=docker/dockerfile:1.4

# Sentinel Lua Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-lua-agent /sentinel-lua-agent

LABEL org.opencontainers.image.title="Sentinel Lua Agent" \
      org.opencontainers.image.description="Sentinel Lua Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-lua"

ENV RUST_LOG=info,sentinel_lua_agent=debug \
    SOCKET_PATH=/var/run/sentinel/lua.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-lua-agent"]
