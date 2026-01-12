//! Sentinel Lua Agent - Scriptable request/response filtering with Lua
//!
//! This agent provides a Lua scripting interface for custom request/response
//! processing in the Sentinel proxy.

use anyhow::{Context, Result};
use clap::Parser;
use mlua::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AgentServer, AuditMetadata, ConfigureEvent, HeaderOp,
    RequestHeadersEvent, ResponseHeadersEvent,
};

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "sentinel-lua-agent")]
#[command(about = "Lua scripting agent for Sentinel reverse proxy")]
struct Args {
    /// Path to Unix socket
    #[arg(long, default_value = "/tmp/sentinel-lua.sock", env = "AGENT_SOCKET")]
    socket: PathBuf,

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

/// Lua agent
pub struct LuaAgent {
    lua: Arc<RwLock<Lua>>,
    #[allow(dead_code)]
    script_path: PathBuf,
    fail_open: bool,
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
        })
    }

    /// Load a new Lua script from content string
    fn load_script_content(&self, script_content: &str) -> Result<()> {
        let mut lua = self.lua.blocking_write();

        // Create a new Lua state
        let new_lua = Lua::new();

        // Load the script
        new_lua.load(script_content)
            .exec()
            .map_err(|e| anyhow::anyhow!("Failed to load script: {}", e))?;

        // Replace the old state with the new one
        *lua = new_lua;

        info!("Lua script loaded from configuration");
        Ok(())
    }

    fn execute_request_script(&self, event: &RequestHeadersEvent) -> Result<ScriptResult> {
        let lua = self.lua.blocking_read();

        // Create request table
        let request_table = lua.create_table().map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        request_table.set("method", event.method.clone()).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        request_table.set("uri", event.uri.clone()).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        request_table.set("client_ip", event.metadata.client_ip.clone()).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        request_table.set("correlation_id", event.metadata.correlation_id.clone()).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

        // Convert headers to Lua table
        let headers_table = lua.create_table().map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        for (name, values) in &event.headers {
            // Join multiple values with comma
            let value = values.join(", ");
            headers_table.set(name.clone(), value).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        }
        request_table.set("headers", headers_table).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

        // Set global request
        lua.globals().set("request", request_table).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

        // Call on_request_headers if it exists
        let func: Option<LuaFunction> = lua.globals().get("on_request_headers").ok();

        if let Some(func) = func {
            let result: LuaValue = func.call(()).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

            // Parse result
            if let LuaValue::Table(result_table) = result {
                return self.parse_script_result(&lua, result_table);
            }
        }

        Ok(ScriptResult::default())
    }

    fn execute_response_script(&self, event: &ResponseHeadersEvent) -> Result<ScriptResult> {
        let lua = self.lua.blocking_read();

        // Create response table
        let response_table = lua.create_table().map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        response_table.set("status", event.status).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        response_table.set("correlation_id", event.correlation_id.clone()).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

        // Convert headers to Lua table
        let headers_table = lua.create_table().map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        for (name, values) in &event.headers {
            let value = values.join(", ");
            headers_table.set(name.clone(), value).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;
        }
        response_table.set("headers", headers_table).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

        // Set global response
        lua.globals().set("response", response_table).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

        // Call on_response_headers if it exists
        let func: Option<LuaFunction> = lua.globals().get("on_response_headers").ok();

        if let Some(func) = func {
            let result: LuaValue = func.call(()).map_err(|e| anyhow::anyhow!("Lua error: {}", e))?;

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
            for pair in headers.pairs::<String, String>() {
                if let Ok((name, value)) = pair {
                    result.add_request_headers.insert(name, value);
                }
            }
        }

        // Parse remove_request_headers
        if let Ok(headers) = table.get::<LuaTable>("remove_request_headers") {
            for value in headers.sequence_values::<String>() {
                if let Ok(name) = value {
                    result.remove_request_headers.push(name);
                }
            }
        }

        // Parse add_response_headers
        if let Ok(headers) = table.get::<LuaTable>("add_response_headers") {
            for pair in headers.pairs::<String, String>() {
                if let Ok((name, value)) = pair {
                    result.add_response_headers.insert(name, value);
                }
            }
        }

        // Parse remove_response_headers
        if let Ok(headers) = table.get::<LuaTable>("remove_response_headers") {
            for value in headers.sequence_values::<String>() {
                if let Ok(name) = value {
                    result.remove_response_headers.push(name);
                }
            }
        }

        // Parse tags
        if let Ok(tags) = table.get::<LuaTable>("tags") {
            for value in tags.sequence_values::<String>() {
                if let Ok(tag) = value {
                    result.tags.push(tag);
                }
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
                    AgentResponse::redirect(url, status)
                        .with_audit(AuditMetadata {
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
impl AgentHandler for LuaAgent {
    async fn on_configure(&self, event: ConfigureEvent) -> AgentResponse {
        info!(
            agent_id = %event.agent_id,
            "Received configuration event"
        );

        // Parse the configuration
        let config: LuaConfigJson = match serde_json::from_value(event.config) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to parse configuration: {}", e);
                return AgentResponse::block(500, Some(format!("Invalid configuration: {}", e)));
            }
        };

        // Load script if provided in config
        if let Some(script_content) = &config.script {
            debug!("Loading Lua script from configuration");
            if let Err(e) = self.load_script_content(script_content) {
                error!("Failed to load Lua script from config: {}", e);
                if config.fail_open {
                    warn!("Failing open due to script load error");
                    return AgentResponse::default_allow()
                        .with_audit(AuditMetadata {
                            tags: vec!["lua".to_string(), "config_error".to_string(), "fail_open".to_string()],
                            reason_codes: vec![format!("SCRIPT_LOAD_ERROR: {}", e)],
                            ..Default::default()
                        });
                } else {
                    return AgentResponse::block(500, Some(format!("Failed to load script: {}", e)));
                }
            }
            info!("Lua script loaded successfully from configuration");
        }

        AgentResponse::default_allow()
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        match self.execute_request_script(&event) {
            Ok(result) => {
                debug!(decision = %result.decision, "Lua script executed");
                self.build_response(result)
            }
            Err(e) => {
                error!("Lua script error: {}", e);
                if self.fail_open {
                    warn!("Failing open due to script error");
                    AgentResponse::default_allow()
                        .with_audit(AuditMetadata {
                            tags: vec!["lua".to_string(), "error".to_string(), "fail_open".to_string()],
                            reason_codes: vec![format!("SCRIPT_ERROR: {}", e)],
                            ..Default::default()
                        })
                } else {
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
                if self.fail_open {
                    AgentResponse::default_allow()
                } else {
                    AgentResponse::block(500, Some("Script execution error".to_string()))
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("{}={},sentinel_agent_protocol=info", env!("CARGO_CRATE_NAME"), log_level))
        .json()
        .init();

    info!("Starting Sentinel Lua Agent");

    // Create agent
    let agent = LuaAgent::new(args.script.clone(), args.fail_open)?;

    info!(
        script = ?args.script,
        fail_open = args.fail_open,
        "Configuration loaded"
    );

    // Start agent server
    info!(socket = ?args.socket, "Starting agent server");
    let server = AgentServer::new(
        "sentinel-lua-agent",
        args.socket,
        Box::new(agent),
    );
    server.run().await.map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(())
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
        let script = create_test_script(r#"
            function on_request_headers()
                return { decision = "allow" }
            end
        "#);

        let agent = LuaAgent::new(script.path().to_path_buf(), false).unwrap();

        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), vec!["example.com".to_string()]);

        let event = RequestHeadersEvent {
            metadata: sentinel_agent_protocol::RequestMetadata {
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
        let script = create_test_script(r#"
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
        "#);

        let agent = LuaAgent::new(script.path().to_path_buf(), false).unwrap();

        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), vec!["example.com".to_string()]);

        let event = RequestHeadersEvent {
            metadata: sentinel_agent_protocol::RequestMetadata {
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
        let script = create_test_script(r#"
            function on_request_headers()
                return {
                    decision = "allow",
                    add_request_headers = {
                        ["X-Processed-By"] = "lua-agent"
                    }
                }
            end
        "#);

        let agent = LuaAgent::new(script.path().to_path_buf(), false).unwrap();

        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), vec!["example.com".to_string()]);

        let event = RequestHeadersEvent {
            metadata: sentinel_agent_protocol::RequestMetadata {
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
}
