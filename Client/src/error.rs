// 错误类型定义
//
// 使用 thiserror 库定义结构化错误类型，确保所有错误都能被正确处理。
// 系统绝不使用 panic! 或 .unwrap()，所有操作都返回 Result 类型。

use thiserror::Error;

/// 客户端错误类型
#[derive(Error, Debug)]
pub enum ClientError {
    /// 连接错误
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
    /// 消息序列化/反序列化错误
    #[error("Message serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    /// 命令执行错误
    #[error("Command execution error: {0}")]
    ExecutionError(String),
    
    /// 系统信息收集错误
    #[error("System info collection error: {0}")]
    SystemInfoError(String),
    
    /// I/O 错误
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    /// WebSocket 协议错误（仅在启用 ws 特性时可用）
    #[cfg(feature = "ws")]
    #[error("WebSocket protocol error: {0}")]
    WebSocketError(#[from] tokio_tungstenite::tungstenite::Error),
}

/// Result 类型别名，简化错误处理
pub type Result<T> = std::result::Result<T, ClientError>;
