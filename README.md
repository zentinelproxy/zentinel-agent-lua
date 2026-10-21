<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Lua agent</h3>

<p align="center">Runs one Lua 5.4 script on request and response headers to allow, block, redirect or rewrite headers.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-lua/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-lua/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Rust: 1.94.1+" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&labelColor=1f161e&logo=rust&logoColor=white">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/lua/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

For request logic that is too specific for a built-in filter and too small
for a compiled agent. The agent loads one script at startup, sets a global
`request` (or `response`) table and calls the script's `on_request_headers()`
or `on_response_headers()`; the table it returns becomes the decision. A
function the script does not define allows. A script error blocks with `500`
unless the agent runs with `--fail-open`; if the agent itself is unreachable,
the filter's `failure-mode` decides.

The script runs with Lua's standard libraries, including `io` and `os`. It is
not sandboxed: treat it as code with the agent's privileges.

## Quick start

```bash
zentinel bundle install lua

cat > handler.lua <<'EOF'
function on_request_headers()
    if request.uri:sub(1, 6) == "/admin" then
        return { decision = "block", status = 403, body = "Forbidden" }
    end
    return { decision = "allow", add_request_headers = { ["X-Processed-By"] = "lua-agent" } }
end
EOF

zentinel-lua-agent --script handler.lua --socket /var/run/zentinel/lua.sock
```

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "127.0.0.1:8080"
        protocol "http"
    }
}

agents {
    agent "lua" type="custom" {
        unix-socket "/var/run/zentinel/lua.sock"
        events "request_headers" "response_headers"
        timeout-ms 100
    }
}

filters {
    filter "lua" {
        type "agent"
        agent "lua"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
        filters "lua"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}
```

## Install

```bash
zentinel bundle install lua
```

Release binaries (`zentinel-lua-agent-<version>-<platform>.tar.gz`) for
`linux-x86_64`, `linux-aarch64` and `darwin-aarch64` are on the
[releases page](https://github.com/zentinelproxy/zentinel-agent-lua/releases).

`cargo install` does not work: the crate is not on crates.io, and it takes
`zentinel-agent-protocol` through a path dependency. To build from source,
check out [zentinel](https://github.com/zentinelproxy/zentinel) next to this
repository:

```bash
git clone https://github.com/zentinelproxy/zentinel
git clone https://github.com/zentinelproxy/zentinel-agent-lua
cd zentinel-agent-lua
cargo build --release
```

## Configuration

| Option | Default | Meaning |
|---|---|---|
| `--script` / `LUA_SCRIPT` | required | Lua file to load at startup |
| `--socket` / `AGENT_SOCKET` | `/tmp/zentinel-lua.sock` | Unix socket to listen on |
| `--grpc-address` / `GRPC_ADDRESS` | none | Also listen on gRPC (e.g. `127.0.0.1:50051`), in addition to the socket |
| `--fail-open` / `FAIL_OPEN` | `false` | On a script error, allow (tags `lua`, `error`, `fail_open`) instead of blocking with `500` |
| `--verbose`, `-v` / `LUA_VERBOSE` | `false` | Debug logging |
| `--max-memory-mb` / `LUA_MAX_MEMORY_MB` | `64` | Lua heap limit (unreleased, `main` only) |
| `--max-instructions` / `LUA_MAX_INSTRUCTIONS` | `1000000` | Instructions per call, checked every 1000; `0` is unlimited (unreleased, `main` only) |

The script is read once; restart the agent to change it. The proxy does not
forward an agent block's `config { }` to the agent, so use the flags above.

### Script API

`request` has `method`, `uri` (path and query), `client_ip`, `correlation_id`
and `headers`; `response` has `status`, `correlation_id` and `headers`.
Header names are **lowercase** (`request.headers["user-agent"]`), repeated
headers are joined with `", "`, and the request headers include the
pseudo-headers `:method` and `:path`.

The returned table:

| Field | Meaning |
|---|---|
| `decision` | `"allow"` (default), `"block"` / `"deny"`, or `"redirect"` |
| `status` | Status for block (default `403`) or redirect (default `302`) |
| `body` | Response body for block; target URL for redirect (a redirect without one allows) |
| `add_request_headers`, `remove_request_headers` | Table of headers to set / list of names to remove upstream (allow only) |
| `add_response_headers`, `remove_response_headers` | The same for the response to the client (allow and block) |
| `tags` | Audit tags |

```lua
function on_request_headers()
    local ua = (request.headers["user-agent"] or ""):lower()
    for _, bot in ipairs({ "sqlmap", "nikto", "masscan" }) do
        if ua:find(bot, 1, true) then
            return { decision = "block", status = 403, tags = { "bot-blocked", bot } }
        end
    end
    return { decision = "allow" }
end

function on_response_headers()
    return { decision = "allow", add_response_headers = { ["X-Content-Type-Options"] = "nosniff" } }
end
```

There is no Zentinel-specific library (no `json`, `crypto`, `http`, `regex`
or `zentinel` modules); use plain Lua.

## Development

CI clones `zentinel` next to the repository before building; do the same locally.

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

## Related

- [Registry page](https://registry.zentinelproxy.io/lua/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [JavaScript agent](https://github.com/zentinelproxy/zentinel-agent-js), the same model in JavaScript
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
