# sentinel-agent-lua

Lua scripting agent for [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy. Write custom request/response processing logic in Lua.

## Features

- Execute Lua scripts on request/response lifecycle events
- Sandboxed execution with resource limits (memory, CPU, time)
- Hot-reload of scripts without restart
- Rich standard library (JSON, crypto, HTTP utilities, regex)
- Script metadata for routing and prioritization
- VM pooling for performance

## Installation

### From crates.io

```bash
cargo install sentinel-agent-lua
```

### From source

```bash
git clone https://github.com/raskell-io/sentinel-agent-lua
cd sentinel-agent-lua
cargo build --release
```

## Usage

```bash
sentinel-lua-agent --socket /var/run/sentinel/lua.sock \
  --scripts /etc/sentinel/scripts
```

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/sentinel-lua.sock` |
| `--scripts` | `LUA_SCRIPTS_DIR` | Scripts directory | `/etc/sentinel/scripts` |
| `--config` | `LUA_CONFIG` | Configuration file | - |
| `--log-level` | `RUST_LOG` | Log level | `info` |

## Writing Scripts

### Script Structure

```lua
-- name: my-script
-- version: 1.0.0
-- hook: request_headers
-- paths: /api/*
-- methods: GET, POST
-- priority: 100

function on_request_headers(request)
    -- Add custom header
    request:add_header("X-Processed-By", "my-script")

    -- Check authorization
    local auth = request:get_header("Authorization")
    if not auth then
        sentinel.set_decision("block")
        return
    end

    sentinel.set_decision("allow")
end
```

### Available Hooks

| Hook | Description |
|------|-------------|
| `on_request_headers(request)` | Called when request headers are received |
| `on_request_body(request, body)` | Called when full request body is buffered |
| `on_request_body_chunk(request, chunk, is_last)` | Called for each body chunk (streaming) |
| `on_response_headers(response)` | Called when response headers are received |
| `on_response_body(response, body)` | Called when full response body is buffered |

### Request/Response API

```lua
-- Request object
request:get_header("name")           -- Get header value
request:add_header("name", "value")  -- Add header
request:remove_header("name")        -- Remove header
request:get_path()                   -- Get request path
request:get_method()                 -- Get HTTP method
request:get_query()                  -- Get query string
request:get_source_ip()              -- Get client IP

-- Response object
response:get_status()                -- Get status code
response:get_header("name")          -- Get header value
response:add_header("name", "value") -- Add header
response:remove_header("name")       -- Remove header
```

### Standard Library

#### JSON
```lua
local obj = json.decode('{"key": "value"}')
local str = json.encode({key = "value"})
local pretty = json.encode_pretty(obj)
```

#### Crypto
```lua
local hash = crypto.sha256("data")
local hash384 = crypto.sha384("data")
local hash512 = crypto.sha512("data")
local mac = crypto.hmac_sha256("key", "message")
local bytes = crypto.random_bytes(32)
local hex = crypto.random_hex(16)
```

#### HTTP Utilities
```lua
local encoded = http.url_encode("hello world")
local decoded = http.url_decode("hello%20world")
local params = http.parse_query("foo=bar&baz=qux")
local query = http.build_query({foo = "bar"})
local cookies = http.parse_cookies(cookie_header)
local text = http.status_text(200)  -- "OK"
```

#### Encoding
```lua
local b64 = encoding.base64_encode("data")
local data = encoding.base64_decode(b64)
local hex = encoding.hex_encode("data")
local data = encoding.hex_decode(hex)
local compressed = encoding.gzip_compress("data")
local data = encoding.gzip_decompress(compressed)
```

#### Regex
```lua
local matched = regex.match("^hello", "hello world")
local found = regex.find("\\d+", "value: 42")
local all = regex.find_all("\\d+", "1 2 3")
local replaced = regex.replace("\\d+", "value: 42", "X")
```

#### Time
```lua
local now = time.now()           -- Unix timestamp
local now_ms = time.now_ms()     -- Milliseconds
local formatted = time.format(now, "%Y-%m-%d")
local ts = time.parse("2024-01-01", "%Y-%m-%d")
```

#### Sentinel
```lua
sentinel.log("info", "message")
sentinel.set_decision("allow")   -- or "block", "redirect"
sentinel.add_metadata("key", "value")
sentinel.version                 -- Agent version
```

## Configuration

### Sentinel Proxy Configuration

```kdl
agents {
    agent "lua" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/sentinel/lua.sock"
        }
        events ["request_headers", "response_headers"]
        timeout-ms 100
        failure-mode "open"
    }
}
```

### Agent Configuration (KDL)

```kdl
socket-path "/var/run/sentinel/lua.sock"

scripts {
    directory "/etc/sentinel/scripts"
    hot-reload true
    watch-interval 5
    timeout 100
    cache-size 200
}

vm-pool {
    size 20
    max-age 600
    max-executions 5000
}

resource-limits {
    max-memory 52428800      // 50MB
    max-instructions 10000000
    max-execution-time 200
    allow-filesystem false
    allow-network false
}

safety {
    fail-open true
    debug-scripts false
    max-concurrent 200
}
```

## Resource Limits

The agent enforces strict resource limits on Lua execution:

| Limit | Default | Description |
|-------|---------|-------------|
| Memory | 50MB | Maximum memory per VM |
| Instructions | 10M | Maximum CPU instructions |
| Execution time | 100ms | Maximum script runtime |
| String length | 10MB | Maximum string size |
| Table size | 10,000 | Maximum table entries |

## Security

Scripts run in a sandboxed environment with:

- No filesystem access (by default)
- No network access (by default)
- No process spawning
- Dangerous functions removed (dofile, loadfile, etc.)
- Limited libraries (string, table, math, utf8, coroutine)

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run -- --socket /tmp/test.sock --scripts ./scripts

# Run tests
cargo test
```

## License

Apache-2.0
