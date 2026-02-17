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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::UnixListener;
use std::sync::RwLock;
use tracing::{debug, error, info, trace, warn};

use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, CounterMetric, DrainReason, GaugeMetric,
    GrpcAgentServerV2, HealthStatus, MetricsReport, ShutdownReason,
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
    /// Fail open on script errors
    #[serde(default)]
    fail_open: bool,
}

/// Lua agent with v2 protocol support
pub struct LuaAgent {
    lua: Arc<RwLock<Lua>>,
    #[allow(dead_code)]
    script_path: PathBuf,
    fail_open: bool,
    /// Metrics counters
    requests_total: AtomicU64,
    requests_blocked: AtomicU64,
    requests_allowed: AtomicU64,
    script_errors: AtomicU64,
}

impl LuaAgent {
    pub fn new(script_path: PathBuf, fail_open: bool) -> Result<Self> {
        let lua = Lua::new();

        // Load the script
        let script_content = std::fs::read_to_string(&script_path)
            .with_context(|| format!("Failed to read script: {:?}", script_path))?;

        lua.load(&script_content)
            .exec()
            .map_err(|e| anyhow::anyhow!("Failed to load script {:?}: {}", script_path, e))?;

        info!(script = ?script_path, "Lua script loaded successfully");

        Ok(Self {
            lua: Arc::new(RwLock::new(lua)),
            script_path,
            fail_open,
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            script_errors: AtomicU64::new(0),
        })
    }

    /// Load a new Lua script from content string
    fn load_script_content(&self, script_content: &str) -> Result<()> {
        let mut lua = self.lua.write().unwrap();

        // Create a new Lua state
        let new_lua = Lua::new();

        // Load the script
        new_lua
            .load(script_content)
            .exec()
            .map_err(|e| anyhow::anyhow!("Failed to load script: {}", e))?;

        // Replace the old state with the new one
        *lua = new_lua;

        info!("Lua script loaded from configuration");
        Ok(())
    }

    fn execute_request_script(&self, event: &RequestHeadersEvent) -> Result<ScriptResult> {
        let lua = self.lua.read().unwrap();

        // Create request table
        let request_table = lua
            .create_table()
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        request_table
            .set("method", event.method.clone())
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        request_table
            .set("uri", event.uri.clone())
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        request_table
            .set("client_ip", event.metadata.client_ip.clone())
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        request_table
            .set("correlation_id", event.metadata.correlation_id.clone())
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

        // Convert headers to Lua table
        let headers_table = lua
            .create_table()
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        for (name, values) in &event.headers {
            // Join multiple values with comma
            let value = values.join(", ");
            headers_table
                .set(name.clone(), value)
                .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        }
        request_table
            .set("headers", headers_table)
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

        // Set global request
        lua.globals()
            .set("request", request_table)
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

        // Call on_request_headers if it exists
        let func: Option<LuaFunction> = lua.globals().get("on_request_headers").ok();

        if let Some(func) = func {
            let result: LuaValue = func
                .call(())
                .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

            // Parse result
            if let LuaValue::Table(result_table) = result {
                return self.parse_script_result(&lua, result_table);
            }
        }

        Ok(ScriptResult::default())
    }

    fn execute_response_script(&self, event: &ResponseHeadersEvent) -> Result<ScriptResult> {
        let lua = self.lua.read().unwrap();

        // Create response table
        let response_table = lua
            .create_table()
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        response_table
            .set("status", event.status)
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        response_table
            .set("correlation_id", event.correlation_id.clone())
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

        // Convert headers to Lua table
        let headers_table = lua
            .create_table()
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        for (name, values) in &event.headers {
            let value = values.join(", ");
            headers_table
                .set(name.clone(), value)
                .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        }
        response_table
            .set("headers", headers_table)
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

        // Set global response
        lua.globals()
            .set("response", response_table)
            .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

        // Call on_response_headers if it exists
        let func: Option<LuaFunction> = lua.globals().get("on_response_headers").ok();

        if let Some(func) = func {
            let result: LuaValue = func
                .call(())
                .map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

            if let LuaValue::Table(result_table) = result {
                return self.parse_script_result(&lua, result_table);
            }
        }

        Ok(ScriptResult::default())
    }

    fn parse_script_result(&self, _lua: &Lua, table: LuaTable) -> Result<ScriptResult> {
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
        AgentCapabilities::new("zentinel-lua-agent", "Zentinel Lua Agent", env!("CARGO_PKG_VERSION"))
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

        // Load script if provided in config
        if let Some(script_content) = &lua_config.script {
            debug!("Loading Lua script from configuration");
            if let Err(e) = self.load_script_content(script_content) {
                error!("Failed to load Lua script from config: {}", e);
                return !lua_config.fail_open;
            }
            info!("Lua script loaded successfully from configuration");
        }

        true
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        match self.execute_request_script(&event) {
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

                if self.fail_open {
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
        match self.execute_response_script(&event) {
            Ok(result) => {
                debug!(decision = %result.decision, "Lua response script executed");
                self.build_response(result)
            }
            Err(e) => {
                error!("Lua response script error: {}", e);
                self.script_errors.fetch_add(1, Ordering::Relaxed);

                if self.fail_open {
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

/// UDS v2 server for the Lua agent
async fn run_uds_server(
    socket_path: PathBuf,
    agent: Arc<LuaAgent>,
) -> Result<(), anyhow::Error> {

    // Remove existing socket file if it exists
    if socket_path.exists() {
        trace!(socket_path = %socket_path.display(), "Removing existing socket file");
        std::fs::remove_file(&socket_path)?;
    }

    // Create Unix socket listener
    let listener = UnixListener::bind(&socket_path)?;

    info!(socket_path = %socket_path.display(), "UDS v2 agent server listening");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                trace!("Accepted new UDS connection");
                let agent = Arc::clone(&agent);
                tokio::spawn(async move {
                    if let Err(e) = handle_uds_connection(stream, agent).await {
                        error!(error = %e, "Error handling UDS connection");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "Failed to accept UDS connection");
            }
        }
    }
}

/// Handle a single UDS connection with v2 protocol
async fn handle_uds_connection(
    stream: tokio::net::UnixStream,
    agent: Arc<LuaAgent>,
) -> Result<(), anyhow::Error> {
    use zentinel_agent_protocol::v2::{
        MessageType, UdsCapabilities, UdsFeatures, UdsHandshakeResponse, UdsLimits,
    };

    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);

    // Read handshake request
    let (msg_type, payload) = read_uds_message(&mut reader).await?;
    if msg_type != MessageType::HandshakeRequest {
        return Err(anyhow::anyhow!(
            "Expected HandshakeRequest, got {:?}",
            msg_type
        ));
    }

    // Parse handshake request (validates JSON structure)
    let _: serde_json::Value = serde_json::from_slice(&payload)?;

    // Build capabilities
    let caps = agent.capabilities();
    let uds_caps = UdsCapabilities {
        agent_id: caps.agent_id.clone(),
        name: caps.name.clone(),
        version: caps.version.clone(),
        supported_events: caps
            .supported_events
            .iter()
            .map(|e| event_type_to_i32(*e))
            .collect(),
        features: UdsFeatures {
            streaming_body: caps.features.streaming_body,
            websocket: caps.features.websocket,
            guardrails: caps.features.guardrails,
            config_push: caps.features.config_push,
            metrics_export: caps.features.metrics_export,
            concurrent_requests: caps.features.concurrent_requests,
            cancellation: caps.features.cancellation,
            flow_control: caps.features.flow_control,
            health_reporting: caps.features.health_reporting,
        },
        limits: UdsLimits {
            max_body_size: caps.limits.max_body_size as u64,
            max_concurrency: caps.limits.max_concurrency,
            preferred_chunk_size: caps.limits.preferred_chunk_size as u64,
        },
    };

    // Send handshake response
    let handshake_resp = UdsHandshakeResponse {
        encoding: zentinel_agent_protocol::v2::UdsEncoding::Json,
        protocol_version: 2,
        capabilities: uds_caps,
        success: true,
        error: None,
    };

    let resp_bytes = serde_json::to_vec(&handshake_resp)?;
    write_uds_message(&mut writer, MessageType::HandshakeResponse, &resp_bytes).await?;

    trace!("UDS v2 handshake complete");

    // Main event loop
    loop {
        let (msg_type, payload) = match read_uds_message(&mut reader).await {
            Ok(m) => m,
            Err(e) => {
                if e.to_string().contains("UnexpectedEof") || e.to_string().contains("connection") {
                    trace!("UDS client disconnected");
                    return Ok(());
                }
                return Err(e);
            }
        };

        let response_bytes = match msg_type {
            MessageType::RequestHeaders => {
                let event: RequestHeadersEvent = serde_json::from_slice(&payload)?;
                let response = agent.on_request_headers(event).await;
                serde_json::to_vec(&response)?
            }
            MessageType::ResponseHeaders => {
                let event: ResponseHeadersEvent = serde_json::from_slice(&payload)?;
                let response = agent.on_response_headers(event).await;
                serde_json::to_vec(&response)?
            }
            MessageType::Configure => {
                #[derive(Deserialize)]
                struct ConfigMsg {
                    config: serde_json::Value,
                    version: Option<String>,
                }
                let config_msg: ConfigMsg = serde_json::from_slice(&payload)?;
                let success = agent.on_configure(config_msg.config, config_msg.version).await;
                serde_json::to_vec(&serde_json::json!({ "success": success }))?
            }
            MessageType::Ping => {
                #[derive(Deserialize)]
                struct Ping {
                    sequence: u64,
                    timestamp_ms: u64,
                }
                let ping: Ping = serde_json::from_slice(&payload)?;
                let pong = serde_json::json!({
                    "sequence": ping.sequence,
                    "ping_timestamp_ms": ping.timestamp_ms,
                    "timestamp_ms": now_ms(),
                });
                let pong_bytes = serde_json::to_vec(&pong)?;
                write_uds_message(&mut writer, MessageType::Pong, &pong_bytes).await?;
                continue;
            }
            MessageType::HealthStatus => {
                // Proxy requesting health status
                let health = agent.health_status();
                serde_json::to_vec(&health)?
            }
            MessageType::MetricsReport => {
                // Proxy requesting metrics
                let metrics = agent.metrics_report();
                serde_json::to_vec(&metrics)?
            }
            _ => {
                trace!(?msg_type, "Received unhandled message type");
                continue;
            }
        };

        write_uds_message(&mut writer, MessageType::AgentResponse, &response_bytes).await?;
    }
}

/// Read a UDS v2 message
async fn read_uds_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(zentinel_agent_protocol::v2::MessageType, Vec<u8>), anyhow::Error> {
    use zentinel_agent_protocol::v2::MessageType;

    // Read length (4 bytes, big-endian)
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let total_len = u32::from_be_bytes(len_bytes) as usize;

    if total_len == 0 {
        return Err(anyhow::anyhow!("Zero-length message"));
    }

    const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
    if total_len > MAX_MESSAGE_SIZE {
        return Err(anyhow::anyhow!(
            "Message too large: {} > {}",
            total_len,
            MAX_MESSAGE_SIZE
        ));
    }

    // Read message type (1 byte)
    let mut type_byte = [0u8; 1];
    reader.read_exact(&mut type_byte).await?;
    let msg_type = MessageType::try_from(type_byte[0])
        .map_err(|e| anyhow::anyhow!("Invalid message type: {}", e))?;

    // Read payload
    let payload_len = total_len - 1;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }

    Ok((msg_type, payload))
}

/// Write a UDS v2 message
async fn write_uds_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg_type: zentinel_agent_protocol::v2::MessageType,
    payload: &[u8],
) -> Result<(), anyhow::Error> {
    // Write length (4 bytes, big-endian) - includes type byte
    let total_len = (payload.len() + 1) as u32;
    writer.write_all(&total_len.to_be_bytes()).await?;

    // Write message type (1 byte)
    writer.write_all(&[msg_type as u8]).await?;

    // Write payload
    writer.write_all(payload).await?;
    writer.flush().await?;

    Ok(())
}

fn event_type_to_i32(event_type: EventType) -> i32 {
    match event_type {
        EventType::Configure => 0,
        EventType::RequestHeaders => 1,
        EventType::RequestBodyChunk => 2,
        EventType::ResponseHeaders => 3,
        EventType::ResponseBodyChunk => 4,
        EventType::RequestComplete => 5,
        EventType::WebSocketFrame => 6,
        EventType::GuardrailInspect => 7,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

    // Create agent
    let agent = Arc::new(LuaAgent::new(args.script.clone(), args.fail_open)?);

    info!(
        script = ?args.script,
        fail_open = args.fail_open,
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
                if let Err(e) = run_uds_server(socket_path, uds_agent).await {
                    error!(error = %e, "UDS server error");
                }
            });

            // Run gRPC server in main task
            let grpc_server = GrpcAgentServerV2::new(
                "zentinel-lua-agent",
                Box::new(LuaAgentWrapper(grpc_agent)),
            );
            grpc_server.run(grpc_addr).await?;

            uds_handle.abort();
        }
        None => {
            // Run only UDS server
            info!(socket = ?args.socket, "Starting agent with UDS (v2 protocol)");
            run_uds_server(args.socket, agent).await?;
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
}
