# syntax=docker/dockerfile:1.4

# Zentinel Lua Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-lua-agent /zentinel-lua-agent

LABEL org.opencontainers.image.title="Zentinel Lua Agent" \
      org.opencontainers.image.description="Zentinel Lua Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-lua"

ENV RUST_LOG=info,zentinel_lua_agent=debug \
    SOCKET_PATH=/var/run/zentinel/lua.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-lua-agent"]
