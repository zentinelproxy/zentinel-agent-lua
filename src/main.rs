//! Zentinel Lua Agent - Scriptable request/response filtering with Lua
//!
//! This agent provides a Lua scripting interface for custom request/response
//! processing in the Zentinel proxy. Supports v2 protocol with both UDS and gRPC transports.

use anyhow::{Context, Result};
use clap::Parser;
use mlua::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::{debug, error, info, warn};

use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, CounterMetric, DrainReason, GaugeMetric,
    GrpcAgentServerV2, HealthStatus, MetricsReport, ShutdownReason, UdsAgentServerV2,
};
use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, EventType, HeaderOp, RequestHeadersEvent, ResponseHeadersEvent,
};

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "zentinel-lua-agent")]
#[command(about = "Lua scripting agent for Zentinel reverse proxy (v2 protocol)")]
#[command(version)]
struct Args {
    /// Path to Unix socket
    #[arg(long, default_value = "/tmp/zentinel-lua.sock", env = "AGENT_SOCKET")]
    socket: PathBuf,

    /// gRPC server address (e.g., "0.0.0.0:50051")
    #[arg(long, value_name = "ADDR", env = "GRPC_ADDRESS")]
    grpc_address: Option<SocketAddr>,

    /// Path to Lua script file
    #[arg(long, env = "LUA_SCRIPT")]
    script: PathBuf,

    /// Enable verbose logging
    #[arg(short, long, env = "LUA_VERBOSE")]
    verbose: bool,

    /// Fail open on script errors
    #[arg(long, env = "FAIL_OPEN")]
    fail_open: bool,

    /// Maximum memory in megabytes for the Lua runtime (default: 64)
    #[arg(long, default_value = "64", env = "LUA_MAX_MEMORY_MB")]
    max_memory_mb: usize,

    /// Maximum instructions per script execution (0 = unlimited, default: 1000000)
    #[arg(long, default_value = "1000000", env = "LUA_MAX_INSTRUCTIONS")]
    max_instructions: u32,
}

/// Lock a mutex, recovering from poisoning (a panic while holding it leaves
/// the VM itself usable).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Lua script result
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScriptResult {
    decision: String,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    add_request_headers: HashMap<String, String>,
    #[serde(default)]
    remove_request_headers: Vec<String>,
    #[serde(default)]
    add_response_headers: HashMap<String, String>,
    #[serde(default)]
    remove_response_headers: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
}

impl Default for ScriptResult {
    fn default() -> Self {
        Self {
            decision: "allow".to_string(),
            status: None,
            body: None,
            add_request_headers: HashMap::new(),
            remove_request_headers: Vec::new(),
            add_response_headers: HashMap::new(),
            remove_response_headers: Vec::new(),
            tags: Vec::new(),
        }
    }
}

/// Configuration received via on_configure event
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct LuaConfigJson {
    /// Inline Lua script content
    #[serde(default)]
    script: Option<String>,
    /// Fail open on script errors (overrides `--fail-open` when present)
    #[serde(default)]
    fail_open: Option<bool>,
}

/// Error message raised when a script runs past its instruction budget.
const INSTRUCTION_LIMIT_ERROR: &str = "Script exceeded instruction limit";

/// Standard libraries a script may use. `io`, `os`, `package` (and with it
/// `require`), `debug` and `coroutine` are not loaded: the first four reach
/// outside the VM, and `coroutine.resume` would catch the instruction-limit
/// error.
fn safe_std_libs() -> mlua::StdLib {
    mlua::StdLib::STRING | mlua::StdLib::TABLE | mlua::StdLib::MATH | mlua::StdLib::UTF8
}

/// Runs after the standard libraries are loaded and before any script.
///
/// - Removes the base-library functions that read files (`dofile`,
///   `loadfile`) and anything `require`-related that may be present.
/// - Restricts `load` to text chunks (binary chunks can corrupt the VM).
/// - Wraps `pcall`/`xpcall` so a script cannot catch the instruction-limit
///   error and keep running: once the budget is spent, they re-raise.
const SANDBOX_PRELUDE: &str = r##"
local raw_pcall, raw_xpcall, raw_load, exceeded, error, select = ...
dofile = nil
loadfile = nil
require = nil
package = nil
local function check(...)
    if exceeded() then
        error("Script exceeded instruction limit", 0)
    end
    return ...
end
pcall = function(...) return check(raw_pcall(...)) end
xpcall = function(...) return check(raw_xpcall(...)) end
load = function(chunk, chunkname, _mode, ...)
    if select("#", ...) > 0 then
        return raw_load(chunk, chunkname, "t", ...)
    end
    return raw_load(chunk, chunkname, "t")
end
"##;

/// A Lua VM with only the safe standard libraries, a memory limit, and an
/// instruction budget applied around every call into script code.
struct Sandbox {
    lua: Lua,
    /// Set once the current call has spent its instruction budget.
    exceeded: Arc<AtomicBool>,
    max_instructions: u32,
}

impl Sandbox {
    fn new(memory_limit: usize, max_instructions: u32) -> Result<Self> {
        let lua = Lua::new_with(safe_std_libs(), LuaOptions::default())
            .map_err(|e| anyhow::anyhow!("Failed to create Lua state: {}", e))?;
        lua.set_memory_limit(memory_limit)?;

        let exceeded = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&exceeded);
        let exceeded_fn = lua.create_function(move |_, ()| Ok(flag.load(Ordering::Relaxed)))?;
        let globals = lua.globals();
        lua.load(SANDBOX_PRELUDE)
            .set_name("=sandbox")
            .call::<()>((
                globals.get::<LuaFunction>("pcall")?,
                globals.get::<LuaFunction>("xpcall")?,
                globals.get::<LuaFunction>("load")?,
                exceeded_fn,
                globals.get::<LuaFunction>("error")?,
                globals.get::<LuaFunction>("select")?,
            ))
            .map_err(|e| anyhow::anyhow!("Failed to initialise Lua sandbox: {}", e))?;

        Ok(Self {
            lua,
            exceeded,
            max_instructions,
        })
    }

    /// Create a sandbox and run a script's top-level code in it, under the
    /// memory and instruction limits.
    fn load(script: &str, name: &str, memory_limit: usize, max_instructions: u32) -> Result<Self> {
        let sandbox = Self::new(memory_limit, max_instructions)?;
        sandbox
            .limited(|lua| lua.load(script).set_name(name).exec())
            .map_err(|e| anyhow::anyhow!("Failed to load script {}: {}", name, e))?;
        Ok(sandbox)
    }

    /// Run `f` with the instruction budget installed; the hook is removed
    /// afterwards whether or not `f` succeeded.
    fn limited<R>(&self, f: impl FnOnce(&Lua) -> LuaResult<R>) -> LuaResult<R> {
        self.exceeded.store(false, Ordering::Relaxed);
        if self.max_instructions > 0 {
            let max = self.max_instructions;
            let counter = AtomicU32::new(0);
            let flag = Arc::clone(&self.exceeded);
            self.lua.set_hook(
                mlua::HookTriggers::new().every_nth_instruction(1000),
                move |_lua, _debug| {
                    let count = counter.fetch_add(1000, Ordering::Relaxed);
                    if count >= max {
                        flag.store(true, Ordering::Relaxed);
                        Err(mlua::Error::RuntimeError(
                            INSTRUCTION_LIMIT_ERROR.to_string(),
                        ))
                    } else {
                        Ok(mlua::VmState::Continue)
                    }
                },
            );
        }
        let result = f(&self.lua);
        self.lua.remove_hook();
        let exceeded = self.exceeded.swap(false, Ordering::Relaxed);
        match result {
            // A script that swallowed the limit error some other way still fails.
            Ok(_) if exceeded => Err(mlua::Error::RuntimeError(
                INSTRUCTION_LIMIT_ERROR.to_string(),
            )),
            other => other,
        }
    }
}

fn lua_err(e: mlua::Error) -> anyhow::Error {
    anyhow::anyhow!("Lua error: {}", e)
}

fn execute_request_script(sandbox: &Sandbox, event: &RequestHeadersEvent) -> Result<ScriptResult> {
    sandbox
        .limited(|lua| {
            // Create request table
            let request_table = lua.create_table()?;
            request_table.set("method", event.method.clone())?;
            request_table.set("uri", event.uri.clone())?;
            request_table.set("client_ip", event.metadata.client_ip.clone())?;
            request_table.set("correlation_id", event.metadata.correlation_id.clone())?;

            // Convert headers to Lua table
            let headers_table = lua.create_table()?;
            for (name, values) in &event.headers {
                // Join multiple values with comma
                headers_table.set(name.clone(), values.join(", "))?;
            }
            request_table.set("headers", headers_table)?;

            // Set global request
            lua.globals().set("request", request_table)?;

            // Call on_request_headers if it exists
            match lua
                .globals()
                .get::<Option<LuaFunction>>("on_request_headers")?
            {
                Some(func) => func.call::<LuaValue>(()),
                None => Ok(LuaValue::Nil),
            }
        })
        .map_err(lua_err)
        .and_then(LuaAgent::script_result)
}

fn execute_response_script(
    sandbox: &Sandbox,
    event: &ResponseHeadersEvent,
) -> Result<ScriptResult> {
    sandbox
        .limited(|lua| {
            // Create response table
            let response_table = lua.create_table()?;
            response_table.set("status", event.status)?;
            response_table.set("correlation_id", event.correlation_id.clone())?;

            // Convert headers to Lua table
            let headers_table = lua.create_table()?;
            for (name, values) in &event.headers {
                headers_table.set(name.clone(), values.join(", "))?;
            }
            response_table.set("headers", headers_table)?;

            // Set global response
            lua.globals().set("response", response_table)?;

            // Call on_response_headers if it exists
            match lua
                .globals()
                .get::<Option<LuaFunction>>("on_response_headers")?
            {
                Some(func) => func.call::<LuaValue>(()),
                None => Ok(LuaValue::Nil),
            }
        })
        .map_err(lua_err)
        .and_then(LuaAgent::script_result)
}

/// Lua agent with v2 protocol support
pub struct LuaAgent {
    /// The script's VM. A `Mutex`, not an `RwLock`: a call sets the global
    /// `request`/`response` and installs a per-call instruction hook, so two
    /// calls must not interleave on one VM. Only locked inside
    /// `spawn_blocking`, never on an async worker thread.
    sandbox: Arc<Mutex<Sandbox>>,
    #[allow(dead_code)]
    script_path: PathBuf,
    fail_open: AtomicBool,
    /// Memory limit in bytes
    memory_limit: usize,
    /// Max instructions per execution (0 = unlimited)
    max_instructions: u32,
    /// Metrics counters
    requests_total: AtomicU64,
    requests_blocked: AtomicU64,
    requests_allowed: AtomicU64,
    script_errors: AtomicU64,
}

impl LuaAgent {
    pub fn new(script_path: PathBuf, fail_open: bool) -> Result<Self> {
        Self::with_limits(script_path, fail_open, 64 * 1024 * 1024, 1_000_000)
    }

    pub fn with_limits(
        script_path: PathBuf,
        fail_open: bool,
        memory_limit: usize,
        max_instructions: u32,
    ) -> Result<Self> {
        // Load the script
        let script_content = std::fs::read_to_string(&script_path)
            .with_context(|| format!("Failed to read script: {:?}", script_path))?;

        let sandbox = Sandbox::load(
            &script_content,
            &format!("@{}", script_path.display()),
            memory_limit,
            max_instructions,
        )?;
        info!(
            memory_limit_mb = memory_limit / (1024 * 1024),
            max_instructions, "Lua memory and instruction limits set"
        );
        info!(script = ?script_path, "Lua script loaded successfully");

        Ok(Self {
            sandbox: Arc::new(Mutex::new(sandbox)),
            script_path,
            fail_open: AtomicBool::new(fail_open),
            memory_limit,
            max_instructions,
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            script_errors: AtomicU64::new(0),
        })
    }

    fn fail_open(&self) -> bool {
        self.fail_open.load(Ordering::Relaxed)
    }

    /// Load a new Lua script from content string. The new VM is built (and
    /// the script's top-level code run, under the limits) without holding the
    /// lock; the lock is only taken to swap it in.
    async fn load_script_content(&self, script_content: &str) -> Result<()> {
        let script = script_content.to_string();
        let (memory_limit, max_instructions) = (self.memory_limit, self.max_instructions);
        let new_sandbox = tokio::task::spawn_blocking(move || {
            Sandbox::load(&script, "=config", memory_limit, max_instructions)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Script load task failed: {}", e))??;

        *lock(&self.sandbox) = new_sandbox;

        info!("Lua script loaded from configuration");
        Ok(())
    }

    #[cfg(test)]
    fn execute_request_script(&self, event: &RequestHeadersEvent) -> Result<ScriptResult> {
        execute_request_script(&lock(&self.sandbox), event)
    }

    /// Run a script call on the blocking pool, so neither the lock nor the
    /// script's execution ties up an async worker thread.
    async fn run_blocking<E: Send + 'static>(
        &self,
        event: E,
        f: fn(&Sandbox, &E) -> Result<ScriptResult>,
    ) -> Result<ScriptResult> {
        let sandbox = Arc::clone(&self.sandbox);
        tokio::task::spawn_blocking(move || f(&lock(&sandbox), &event))
            .await
            .map_err(|e| anyhow::anyhow!("Script task failed: {}", e))?
    }

    fn script_result(value: LuaValue) -> Result<ScriptResult> {
        match value {
            LuaValue::Table(table) => Self::parse_script_result(table),
            _ => Ok(ScriptResult::default()),
        }
    }

    fn parse_script_result(table: LuaTable) -> Result<ScriptResult> {
        let mut result = ScriptResult::default();

        // Parse decision
        if let Ok(decision) = table.get::<String>("decision") {
            result.decision = decision;
        }

        // Parse status
        if let Ok(status) = table.get::<u16>("status") {
            result.status = Some(status);
        }

        // Parse body
        if let Ok(body) = table.get::<String>("body") {
            result.body = Some(body);
        }

        // Parse add_request_headers
        if let Ok(headers) = table.get::<LuaTable>("add_request_headers") {
            for (name, value) in headers.pairs::<String, String>().flatten() {
                result.add_request_headers.insert(name, value);
            }
        }

        // Parse remove_request_headers
        if let Ok(headers) = table.get::<LuaTable>("remove_request_headers") {
            for name in headers.sequence_values::<String>().flatten() {
                result.remove_request_headers.push(name);
            }
        }

        // Parse add_response_headers
        if let Ok(headers) = table.get::<LuaTable>("add_response_headers") {
            for (name, value) in headers.pairs::<String, String>().flatten() {
                result.add_response_headers.insert(name, value);
            }
        }

        // Parse remove_response_headers
        if let Ok(headers) = table.get::<LuaTable>("remove_response_headers") {
            for name in headers.sequence_values::<String>().flatten() {
                result.remove_response_headers.push(name);
            }
        }

        // Parse tags
        if let Ok(tags) = table.get::<LuaTable>("tags") {
            for tag in tags.sequence_values::<String>().flatten() {
                result.tags.push(tag);
            }
        }

        Ok(result)
    }

    fn build_response(&self, result: ScriptResult) -> AgentResponse {
        match result.decision.to_lowercase().as_str() {
            "block" | "deny" => {
                let status = result.status.unwrap_or(403);
                let mut response = AgentResponse::block(status, result.body);

                // Add response headers
                for (name, value) in result.add_response_headers {
                    response = response.add_response_header(HeaderOp::Set { name, value });
                }
                for name in result.remove_response_headers {
                    response = response.add_response_header(HeaderOp::Remove { name });
                }

                response.with_audit(AuditMetadata {
                    tags: result.tags,
                    ..Default::default()
                })
            }
            "redirect" => {
                if let Some(url) = result.body {
                    let status = result.status.unwrap_or(302);
                    AgentResponse::redirect(url, status).with_audit(AuditMetadata {
                        tags: result.tags,
                        ..Default::default()
                    })
                } else {
                    AgentResponse::default_allow()
                }
            }
            _ => {
                // Allow with potential mutations
                let mut response = AgentResponse::default_allow();

                // Add request headers
                for (name, value) in result.add_request_headers {
                    response = response.add_request_header(HeaderOp::Set { name, value });
                }
                for name in result.remove_request_headers {
                    response = response.add_request_header(HeaderOp::Remove { name });
                }

                // Add response headers
                for (name, value) in result.add_response_headers {
                    response = response.add_response_header(HeaderOp::Set { name, value });
                }
                for name in result.remove_response_headers {
                    response = response.add_response_header(HeaderOp::Remove { name });
                }

                if !result.tags.is_empty() {
                    response = response.with_audit(AuditMetadata {
                        tags: result.tags,
                        ..Default::default()
                    });
                }

                response
            }
        }
    }
}

#[async_trait::async_trait]
impl AgentHandlerV2 for LuaAgent {
    /// Get agent capabilities
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(
            "zentinel-lua-agent",
            "Zentinel Lua Agent",
            env!("CARGO_PKG_VERSION"),
        )
        .with_event(EventType::RequestHeaders)
        .with_event(EventType::ResponseHeaders)
        .with_features(AgentFeatures {
            streaming_body: false,
            websocket: false,
            guardrails: false,
            config_push: true,
            metrics_export: true,
            concurrent_requests: 100,
            cancellation: false,
            flow_control: false,
            health_reporting: true,
        })
    }

    /// Handle configuration update
    async fn on_configure(&self, config: serde_json::Value, _version: Option<String>) -> bool {
        info!("Received configuration event");

        // Parse the configuration
        let lua_config: LuaConfigJson = match serde_json::from_value(config) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to parse configuration: {}", e);
                return false;
            }
        };

        let fail_open = lua_config.fail_open.unwrap_or_else(|| self.fail_open());

        // Load script if provided in config
        if let Some(script_content) = &lua_config.script {
            debug!("Loading Lua script from configuration");
            if let Err(e) = self.load_script_content(script_content).await {
                error!("Failed to load Lua script from config: {}", e);
                if !fail_open {
                    // Fail closed: refuse the configuration.
                    return false;
                }
                warn!("Fail-open: accepting configuration, keeping the previous script");
            } else {
                info!("Lua script loaded successfully from configuration");
            }
        }

        self.fail_open.store(fail_open, Ordering::Relaxed);
        true
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        match self.run_blocking(event, execute_request_script).await {
            Ok(result) => {
                debug!(decision = %result.decision, "Lua script executed");
                let response = self.build_response(result.clone());

                // Update metrics based on decision
                if result.decision.to_lowercase() == "block"
                    || result.decision.to_lowercase() == "deny"
                {
                    self.requests_blocked.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.requests_allowed.fetch_add(1, Ordering::Relaxed);
                }

                response
            }
            Err(e) => {
                error!("Lua script error: {}", e);
                self.script_errors.fetch_add(1, Ordering::Relaxed);

                if self.fail_open() {
                    warn!("Failing open due to script error");
                    self.requests_allowed.fetch_add(1, Ordering::Relaxed);
                    AgentResponse::default_allow().with_audit(AuditMetadata {
                        tags: vec![
                            "lua".to_string(),
                            "error".to_string(),
                            "fail_open".to_string(),
                        ],
                        reason_codes: vec![format!("SCRIPT_ERROR: {}", e)],
                        ..Default::default()
                    })
                } else {
                    self.requests_blocked.fetch_add(1, Ordering::Relaxed);
                    AgentResponse::block(500, Some("Script execution error".to_string()))
                        .with_audit(AuditMetadata {
                            tags: vec!["lua".to_string(), "error".to_string()],
                            reason_codes: vec![format!("SCRIPT_ERROR: {}", e)],
                            ..Default::default()
                        })
                }
            }
        }
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        match self.run_blocking(event, execute_response_script).await {
            Ok(result) => {
                debug!(decision = %result.decision, "Lua response script executed");
                self.build_response(result)
            }
            Err(e) => {
                error!("Lua response script error: {}", e);
                self.script_errors.fetch_add(1, Ordering::Relaxed);

                if self.fail_open() {
                    AgentResponse::default_allow()
                } else {
                    AgentResponse::block(500, Some("Script execution error".to_string()))
                }
            }
        }
    }

    /// Get current health status
    fn health_status(&self) -> HealthStatus {
        let error_count = self.script_errors.load(Ordering::Relaxed);
        let total_count = self.requests_total.load(Ordering::Relaxed);

        // If error rate is high, report degraded
        if total_count > 100 && error_count > total_count / 10 {
            HealthStatus::degraded(
                "zentinel-lua-agent",
                vec!["script_execution".to_string()],
                1.5, // 50% slower timeout for degraded state
            )
        } else {
            HealthStatus::healthy("zentinel-lua-agent")
        }
    }

    /// Get current metrics report
    fn metrics_report(&self) -> Option<MetricsReport> {
        let mut report = MetricsReport::new("zentinel-lua-agent", 10_000);

        report.counters.push(CounterMetric::new(
            "lua_requests_total",
            self.requests_total.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "lua_requests_blocked",
            self.requests_blocked.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "lua_requests_allowed",
            self.requests_allowed.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "lua_script_errors",
            self.script_errors.load(Ordering::Relaxed),
        ));

        // Add error rate as gauge
        let total = self.requests_total.load(Ordering::Relaxed);
        let errors = self.script_errors.load(Ordering::Relaxed);
        let error_rate = if total > 0 {
            (errors as f64) / (total as f64)
        } else {
            0.0
        };
        report
            .gauges
            .push(GaugeMetric::new("lua_error_rate", error_rate));

        Some(report)
    }

    /// Handle shutdown request
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            ?reason,
            grace_period_ms, "Received shutdown request, cleaning up"
        );
        // Lua agent doesn't need special cleanup, but log the event
    }

    /// Handle drain request
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(?reason, duration_ms, "Received drain request");
        // Lua agent processes requests synchronously, nothing to drain
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!(
            "{}={},zentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
        .json()
        .init();

    info!("Starting Zentinel Lua Agent (v2 protocol)");

    // Create agent with resource limits
    let memory_limit = args.max_memory_mb * 1024 * 1024;
    let agent = Arc::new(LuaAgent::with_limits(
        args.script.clone(),
        args.fail_open,
        memory_limit,
        args.max_instructions,
    )?);

    info!(
        script = ?args.script,
        fail_open = args.fail_open,
        max_memory_mb = args.max_memory_mb,
        max_instructions = args.max_instructions,
        "Configuration loaded"
    );

    // Start servers based on configuration
    match args.grpc_address {
        Some(grpc_addr) => {
            // Run both UDS and gRPC servers
            info!(
                grpc_address = %grpc_addr,
                socket = %args.socket.display(),
                "Starting agent with gRPC and UDS (v2 protocol)"
            );

            let uds_agent = Arc::clone(&agent);
            let grpc_agent = Arc::clone(&agent);
            let socket_path = args.socket.clone();

            // Spawn UDS server
            let uds_handle = tokio::spawn(async move {
                let server = UdsAgentServerV2::new(
                    "zentinel-lua-agent",
                    socket_path,
                    Box::new(LuaAgentWrapper(uds_agent)),
                );
                if let Err(e) = server.run().await {
                    error!(error = %e, "UDS server error");
                }
            });

            // Run gRPC server in main task
            let grpc_server =
                GrpcAgentServerV2::new("zentinel-lua-agent", Box::new(LuaAgentWrapper(grpc_agent)));
            grpc_server.run(grpc_addr).await?;

            uds_handle.abort();
        }
        None => {
            // Run only UDS server
            info!(socket = ?args.socket, "Starting agent with UDS (v2 protocol)");
            let server = UdsAgentServerV2::new(
                "zentinel-lua-agent",
                args.socket,
                Box::new(LuaAgentWrapper(agent)),
            );
            server.run().await?;
        }
    }

    Ok(())
}

/// Wrapper to implement AgentHandlerV2 for Arc<LuaAgent>
struct LuaAgentWrapper(Arc<LuaAgent>);

#[async_trait::async_trait]
impl AgentHandlerV2 for LuaAgentWrapper {
    fn capabilities(&self) -> AgentCapabilities {
        self.0.capabilities()
    }

    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        self.0.on_configure(config, version).await
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.0.on_request_headers(event).await
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        self.0.on_response_headers(event).await
    }

    fn health_status(&self) -> HealthStatus {
        self.0.health_status()
    }

    fn metrics_report(&self) -> Option<MetricsReport> {
        self.0.metrics_report()
    }

    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        self.0.on_shutdown(reason, grace_period_ms).await
    }

    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        self.0.on_drain(duration_ms, reason).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_script(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[test]
    fn test_allow_script() {
        let script = create_test_script(
            r#"
            function on_request_headers()
                return { decision = "allow" }
            end
        "#,
        );

        let agent = LuaAgent::new(script.path().to_path_buf(), false).unwrap();

        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), vec!["example.com".to_string()]);

        let event = RequestHeadersEvent {
            metadata: zentinel_agent_protocol::RequestMetadata {
                correlation_id: "test-123".to_string(),
                request_id: "req-456".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 12345,
                server_name: Some("example.com".to_string()),
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                traceparent: None,
            },
            method: "GET".to_string(),
            uri: "/test".to_string(),
            headers,
        };

        let result = agent.execute_request_script(&event).unwrap();
        assert_eq!(result.decision, "allow");
    }

    #[test]
    fn test_block_script() {
        let script = create_test_script(
            r#"
            function on_request_headers()
                if request.uri == "/admin" then
                    return {
                        decision = "block",
                        status = 403,
                        body = "Forbidden"
                    }
                end
                return { decision = "allow" }
            end
        "#,
        );

        let agent = LuaAgent::new(script.path().to_path_buf(), false).unwrap();

        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), vec!["example.com".to_string()]);

        let event = RequestHeadersEvent {
            metadata: zentinel_agent_protocol::RequestMetadata {
                correlation_id: "test-123".to_string(),
                request_id: "req-456".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 12345,
                server_name: Some("example.com".to_string()),
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                traceparent: None,
            },
            method: "GET".to_string(),
            uri: "/admin".to_string(),
            headers,
        };

        let result = agent.execute_request_script(&event).unwrap();
        assert_eq!(result.decision, "block");
        assert_eq!(result.status, Some(403));
    }

    #[test]
    fn test_add_headers_script() {
        let script = create_test_script(
            r#"
            function on_request_headers()
                return {
                    decision = "allow",
                    add_request_headers = {
                        ["X-Processed-By"] = "lua-agent"
                    }
                }
            end
        "#,
        );

        let agent = LuaAgent::new(script.path().to_path_buf(), false).unwrap();

        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), vec!["example.com".to_string()]);

        let event = RequestHeadersEvent {
            metadata: zentinel_agent_protocol::RequestMetadata {
                correlation_id: "test-123".to_string(),
                request_id: "req-456".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 12345,
                server_name: Some("example.com".to_string()),
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                traceparent: None,
            },
            method: "GET".to_string(),
            uri: "/test".to_string(),
            headers,
        };

        let result = agent.execute_request_script(&event).unwrap();
        assert_eq!(result.decision, "allow");
        assert_eq!(
            result.add_request_headers.get("X-Processed-By"),
            Some(&"lua-agent".to_string())
        );
    }

    #[test]
    fn test_capabilities() {
        let script = create_test_script(
            r#"
            function on_request_headers()
                return { decision = "allow" }
            end
        "#,
        );

        let agent = LuaAgent::new(script.path().to_path_buf(), false).unwrap();
        let caps = agent.capabilities();

        assert_eq!(caps.agent_id, "zentinel-lua-agent");
        assert!(caps.supports_event(EventType::RequestHeaders));
        assert!(caps.supports_event(EventType::ResponseHeaders));
        assert!(caps.features.config_push);
        assert!(caps.features.metrics_export);
        assert!(caps.features.health_reporting);
    }

    #[test]
    fn test_health_status_healthy() {
        let script = create_test_script(
            r#"
            function on_request_headers()
                return { decision = "allow" }
            end
        "#,
        );

        let agent = LuaAgent::new(script.path().to_path_buf(), false).unwrap();
        let health = agent.health_status();

        assert!(health.is_healthy());
    }

    #[test]
    fn test_metrics_report() {
        let script = create_test_script(
            r#"
            function on_request_headers()
                return { decision = "allow" }
            end
        "#,
        );

        let agent = LuaAgent::new(script.path().to_path_buf(), false).unwrap();
        let metrics = agent.metrics_report();

        assert!(metrics.is_some());
        let report = metrics.unwrap();
        assert_eq!(report.agent_id, "zentinel-lua-agent");
        assert!(!report.counters.is_empty());
        assert!(!report.gauges.is_empty());
    }

    fn request_event(uri: &str) -> RequestHeadersEvent {
        RequestHeadersEvent {
            metadata: zentinel_agent_protocol::RequestMetadata {
                correlation_id: "test-123".to_string(),
                request_id: "req-456".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 12345,
                server_name: None,
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                traceparent: None,
            },
            method: "GET".to_string(),
            uri: uri.to_string(),
            headers: HashMap::new(),
        }
    }

    fn agent_with(script: &str, fail_open: bool) -> Result<LuaAgent> {
        let file = create_test_script(script);
        LuaAgent::with_limits(
            file.path().to_path_buf(),
            fail_open,
            64 * 1024 * 1024,
            100_000,
        )
    }

    fn block_status(response: &AgentResponse) -> Option<u16> {
        match &response.decision {
            zentinel_agent_protocol::Decision::Block { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Reports, as tags, every dangerous global or library function that is
    /// reachable from a script.
    const PROBE_SCRIPT: &str = r#"
        local function reachable()
            local found = {}
            local function probe(name, value)
                if value ~= nil then table.insert(found, name) end
            end
            probe("io", io)
            probe("os", os)
            probe("package", package)
            probe("require", require)
            probe("dofile", dofile)
            probe("loadfile", loadfile)
            probe("debug", debug)
            probe("coroutine", coroutine)
            probe("os.execute", os and os.execute)
            probe("io.open", io and io.open)
            probe("io.popen", io and io.popen)
            -- load must refuse binary chunks
            local ok_bin = load(string.dump(function() return 1 end))
            probe("load(binary)", ok_bin)
            -- and must still accept text chunks
            if load("return 1")() ~= 1 then table.insert(found, "load(text) broken") end
            return found
        end
        load_time = reachable()
        function on_request_headers()
            local tags = {}
            for _, v in ipairs(load_time) do table.insert(tags, "load:" .. v) end
            for _, v in ipairs(reachable()) do table.insert(tags, "call:" .. v) end
            return { decision = "allow", tags = tags }
        end
    "#;

    #[test]
    fn test_sandbox_dangerous_globals_unavailable_from_file_script() {
        let agent = agent_with(PROBE_SCRIPT, false).unwrap();
        let result = agent.execute_request_script(&request_event("/")).unwrap();
        assert_eq!(result.tags, Vec::<String>::new());
    }

    #[test]
    fn test_sandbox_dangerous_calls_fail() {
        for call in [
            r#"os.execute("true")"#,
            r#"io.open("/etc/passwd")"#,
            r#"require("os")"#,
            r#"dofile("/etc/passwd")"#,
            r#"loadfile("/etc/passwd")"#,
        ] {
            let err = agent_with(call, false).err().unwrap().to_string();
            assert!(err.contains("attempt to"), "{call}: {err}");
        }
    }

    #[tokio::test]
    async fn test_sandbox_applies_to_inline_config_script() {
        let agent = agent_with("function on_request_headers() end", false).unwrap();
        let accepted = agent
            .on_configure(serde_json::json!({ "script": PROBE_SCRIPT }), None)
            .await;
        assert!(accepted);
        let response = agent.on_request_headers(request_event("/")).await;
        assert_eq!(block_status(&response), None);
        assert!(response.audit.tags.is_empty(), "{:?}", response.audit.tags);
    }

    #[test]
    fn test_instruction_limit_stops_infinite_loop_at_load() {
        let err = agent_with("while true do end", false)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains(INSTRUCTION_LIMIT_ERROR), "{err}");
    }

    #[test]
    fn test_instruction_limit_cannot_be_caught_with_pcall() {
        for script in [
            "while true do pcall(function() while true do end end) end",
            "while true do xpcall(function() while true do end end, function(e) return e end) end",
            "local ok = pcall(function() while true do end end)",
        ] {
            let err = agent_with(script, false).err().unwrap().to_string();
            assert!(err.contains(INSTRUCTION_LIMIT_ERROR), "{script}: {err}");
        }
    }

    #[test]
    fn test_memory_limit_applies_at_load() {
        let file = create_test_script(r#"big = string.rep("x", 8 * 1024 * 1024)"#);
        let err = LuaAgent::with_limits(file.path().to_path_buf(), false, 4 * 1024 * 1024, 0)
            .err()
            .unwrap()
            .to_string();
        assert!(err.to_lowercase().contains("memory"), "{err}");
    }

    #[tokio::test]
    async fn test_instruction_limit_stops_infinite_loop_in_inline_config_script() {
        let agent = agent_with(
            r#"function on_request_headers() return { decision = "block", status = 418 } end"#,
            false,
        )
        .unwrap();
        let accepted = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            agent.on_configure(serde_json::json!({ "script": "while true do end" }), None),
        )
        .await
        .expect("load-time infinite loop must be stopped");
        assert!(
            !accepted,
            "fail-closed: a script that fails to load is refused"
        );
        // Previous script is still in place.
        let response = agent.on_request_headers(request_event("/")).await;
        assert_eq!(block_status(&response), Some(418));
    }

    #[tokio::test]
    async fn test_instruction_limit_at_request_time_then_recovers() {
        let agent = agent_with(
            r#"
            function on_request_headers()
                if request.uri == "/spin" then while true do end end
                return { decision = "allow" }
            end
            "#,
            false,
        )
        .unwrap();
        let response = agent.on_request_headers(request_event("/spin")).await;
        assert_eq!(block_status(&response), Some(500));
        let response = agent.on_request_headers(request_event("/")).await;
        assert_eq!(block_status(&response), None);
    }

    const ERRORING_SCRIPT: &str = r#"
        function on_request_headers() error("boom") end
        function on_response_headers() error("boom") end
    "#;

    #[tokio::test]
    async fn test_script_error_fail_closed_blocks_500() {
        let agent = agent_with(ERRORING_SCRIPT, false).unwrap();
        let response = agent.on_request_headers(request_event("/")).await;
        assert_eq!(block_status(&response), Some(500));
        assert_eq!(agent.requests_blocked.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_script_error_fail_open_allows() {
        let agent = agent_with(ERRORING_SCRIPT, true).unwrap();
        let response = agent.on_request_headers(request_event("/")).await;
        assert_eq!(block_status(&response), None);
        assert!(response.audit.tags.contains(&"fail_open".to_string()));
    }

    #[tokio::test]
    async fn test_configure_load_failure_fail_closed_refuses() {
        let agent = agent_with(
            r#"function on_request_headers() return { decision = "block", status = 418 } end"#,
            false,
        )
        .unwrap();
        let accepted = agent
            .on_configure(serde_json::json!({ "script": "this is not lua" }), None)
            .await;
        assert!(!accepted);
        let accepted = agent
            .on_configure(
                serde_json::json!({ "script": "this is not lua", "fail-open": false }),
                None,
            )
            .await;
        assert!(!accepted);
        assert!(!agent.fail_open());
        let response = agent.on_request_headers(request_event("/")).await;
        assert_eq!(block_status(&response), Some(418));
    }

    #[tokio::test]
    async fn test_configure_load_failure_fail_open_accepts_and_keeps_script() {
        let agent = agent_with(
            r#"function on_request_headers() return { decision = "block", status = 418 } end"#,
            false,
        )
        .unwrap();
        let accepted = agent
            .on_configure(
                serde_json::json!({ "script": "this is not lua", "fail-open": true }),
                None,
            )
            .await;
        assert!(accepted);
        assert!(agent.fail_open());
        let response = agent.on_request_headers(request_event("/")).await;
        assert_eq!(block_status(&response), Some(418));
    }

    #[tokio::test]
    async fn test_configure_fail_open_governs_request_errors() {
        let agent = agent_with(ERRORING_SCRIPT, false).unwrap();
        assert!(
            agent
                .on_configure(serde_json::json!({ "fail-open": true }), None)
                .await
        );
        let response = agent.on_request_headers(request_event("/")).await;
        assert_eq!(block_status(&response), None);

        // Omitting the key keeps the current setting (here: the CLI value).
        let agent = agent_with(ERRORING_SCRIPT, true).unwrap();
        assert!(agent.on_configure(serde_json::json!({}), None).await);
        assert!(agent.fail_open());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_requests_see_their_own_request() {
        let agent = Arc::new(
            agent_with(
                r#"
                function on_request_headers()
                    local uri = request.uri
                    for i = 1, 2000 do end
                    return { decision = "allow", tags = { uri, request.uri } }
                end
                "#,
                false,
            )
            .unwrap(),
        );
        let mut handles = Vec::new();
        for i in 0..64 {
            let agent = Arc::clone(&agent);
            handles.push(tokio::spawn(async move {
                let uri = format!("/{i}");
                let response = agent.on_request_headers(request_event(&uri)).await;
                assert_eq!(response.audit.tags, vec![uri.clone(), uri]);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }
}
