// WebSocket 连接管理模块
//
// 负责建立和维护与服务端的 WebSocket 连接。
// 实现指数退避重连策略，确保连接的可靠性。
//
// 注意：此模块已被 transport 模块取代，保留用于向后兼容。
// 新代码应使用 transport::create_transport() 和 Transport trait。

#[cfg(feature = "ws")]
use crate::backoff::ExponentialBackoff;
#[cfg(feature = "ws")]
use crate::error::Result;
#[cfg(feature = "ws")]
use futures_util::stream::{SplitSink, SplitStream};
#[cfg(feature = "ws")]
use log::{error, info, warn};
#[cfg(feature = "ws")]
use tokio::net::TcpStream;
#[cfg(feature = "ws")]
use tokio::time::sleep;
#[cfg(feature = "ws")]
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
#[cfg(feature = "ws")]
use tokio_tungstenite::tungstenite::Message;

/// WebSocket 流类型别名
#[cfg(feature = "ws")]
pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
#[cfg(feature = "ws")]
pub type WsWriter = SplitSink<WsStream, Message>;
#[cfg(feature = "ws")]
pub type WsReader = SplitStream<WsStream>;

/// 连接管理器
/// 
/// 负责建立和维护与服务端的 WebSocket 连接。
/// 使用指数退避策略处理连接失败和重连。
#[cfg(feature = "ws")]
pub struct ConnectionManager {
    /// 服务器 URL
    server_url: String,
    /// 指数退避策略
    backoff: ExponentialBackoff,
}

#[cfg(feature = "ws")]
impl ConnectionManager {
    /// 创建新的连接管理器
    /// 
    /// # 参数
    /// 
    /// * `server_url` - WebSocket 服务器地址 (例如: "ws://127.0.0.1:8080/ws")
    pub fn new(server_url: String) -> Self {
        Self {
            server_url,
            backoff: ExponentialBackoff::new(),
        }
    }
    
    /// 连接到服务器
    /// 
    /// 该方法会尝试连接到服务器，如果失败会使用指数退避策略自动重试。
    /// 连接成功后会重置退避计时器。
    /// 
    /// # 返回值
    /// 
    /// 返回成功建立的 WebSocket 连接流。
    /// 
    /// # 错误
    /// 
    /// 该方法会持续重试直到连接成功，理论上不会返回错误。
    /// 但如果遇到无法恢复的错误（如 URL 格式错误），会返回 `ClientError`。
    pub async fn connect(&mut self) -> Result<WsStream> {
        loop {
            info!("Connecting to {}...", self.server_url);
            
            match connect_async(&self.server_url).await {
                Ok((ws_stream, response)) => {
                    info!("Connected to server successfully!");
                    info!("Response status: {}", response.status());
                    
                    // 连接成功，重置退避计时器
                    self.backoff.reset();
                    
                    return Ok(ws_stream);
                }
                Err(e) => {
                    // 连接失败，获取下一次重连延迟
                    let delay = self.backoff.next_delay();
                    
                    error!(
                        "Failed to connect to {}: {}. Retrying in {} seconds...",
                        self.server_url,
                        e,
                        delay.as_secs()
                    );
                    
                    // 等待指定时间后重试
                    sleep(delay).await;
                }
            }
        }
    }
    
    /// 处理连接断开，自动重连
    /// 
    /// 当检测到连接断开时调用此方法，它会自动尝试重新连接。
    /// 
    /// # 返回值
    /// 
    /// 返回新建立的 WebSocket 连接流。
    pub async fn reconnect(&mut self) -> Result<WsStream> {
        warn!("Connection lost, attempting to reconnect...");
        self.connect().await
    }
    
    /// 获取服务器 URL
    pub fn server_url(&self) -> &str {
        &self.server_url
    }
}

#[cfg(all(test, feature = "ws"))]
mod tests {
    use super::*;

    #[test]
    fn test_connection_manager_creation() {
        let manager = ConnectionManager::new("ws://127.0.0.1:8080/ws".to_string());
        assert_eq!(manager.server_url(), "ws://127.0.0.1:8080/ws");
    }

    #[test]
    fn test_server_url_getter() {
        let manager = ConnectionManager::new("ws://localhost:9000/test".to_string());
        assert_eq!(manager.server_url(), "ws://localhost:9000/test");
    }
    
    // 注意：实际的连接测试需要运行中的服务器，
    // 这些测试将在集成测试中进行
}
