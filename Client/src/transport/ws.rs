// WebSocket 传输实现
//
// 实现 Transport trait，封装 tokio-tungstenite 的 WebSocket 逻辑。
// 包含指数退避重连策略和连接管理。
// 支持 AES-256-GCM 加密通信。

use crate::backoff::ExponentialBackoff;
use crate::config::get_aes_key;
use crate::crypto;
use crate::error::{ClientError, Result};
use crate::transport::Transport;
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tokio_tungstenite::tungstenite::Message;

/// WebSocket 流类型别名
pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// WebSocket 传输实现
/// 
/// 封装 WebSocket 连接逻辑，实现 Transport trait。
/// 包含指数退避重连策略，确保连接的可靠性。
/// 支持 AES-256-GCM 加密，所有发送和接收的数据都会自动加密/解密。
pub struct WebSocketTransport {
    /// 服务器 URL
    url: String,
    /// WebSocket 连接流（Option 用于表示连接状态）
    stream: Option<WsStream>,
    /// 指数退避策略
    backoff: ExponentialBackoff,
    /// AES-256 加密密钥
    aes_key: Vec<u8>,
}

impl WebSocketTransport {
    /// 创建新的 WebSocket 传输
    /// 
    /// # 参数
    /// 
    /// * `url` - WebSocket 服务器地址 (例如: "ws://127.0.0.1:8080/ws")
    /// 
    /// # 注意
    /// 
    /// URL 会自动处理 null 字节填充（来自二进制修补）。
    /// AES 密钥从配置中自动加载。
    pub fn new(url: String) -> Self {
        // 清理 URL：去除 null 字节和空白字符
        // 这是为了处理 Go 服务端在二进制修补时添加的 \0 填充
        let cleaned_url = url
            .trim_matches('\0')           // 去除前后的 null 字节
            .trim_matches(char::from(0))  // 额外保险：再次去除 null 字节
            .trim()                       // 去除空白字符
            .to_string();
        
        debug!("WebSocketTransport created with URL: {}", cleaned_url);
        
        // 加载 AES 密钥
        let aes_key = get_aes_key();
        debug!("AES key loaded: {} bytes", aes_key.len());
        
        Self {
            url: cleaned_url,
            stream: None,
            backoff: ExponentialBackoff::new(),
            aes_key,
        }
    }
    
    /// 获取服务器 URL
    pub fn url(&self) -> &str {
        &self.url
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn connect(&mut self) -> Result<()> {
        loop {
            info!("Connecting to {}...", self.url);
            
            match connect_async(&self.url).await {
                Ok((ws_stream, response)) => {
                    info!("Connected to server successfully!");
                    info!("Response status: {}", response.status());
                    
                    // 连接成功，保存流并重置退避计时器
                    self.stream = Some(ws_stream);
                    self.backoff.reset();
                    
                    return Ok(());
                }
                Err(e) => {
                    // 连接失败，获取下一次重连延迟
                    let delay = self.backoff.next_delay();
                    
                    error!(
                        "Failed to connect to {}: {}. Retrying in {} seconds...",
                        self.url,
                        e,
                        delay.as_secs()
                    );
                    
                    // 等待指定时间后重试
                    sleep(delay).await;
                }
            }
        }
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        // 检查连接是否存在
        let stream = self.stream.as_mut().ok_or_else(|| {
            ClientError::ConnectionError("Not connected".to_string())
        })?;
        
        debug!("Encrypting {} bytes before sending", data.len());
        
        // 加密数据
        let encrypted = crypto::encrypt(data, &self.aes_key);
        
        // 报文混淆
        let obfuscated = crypto::obfuscate_packet(encrypted);
        
        debug!("Obfuscated data: {} bytes", obfuscated.len());
        
        // 发送二进制消息（加密后的数据）
        stream.send(Message::Binary(obfuscated)).await
            .map_err(|e| ClientError::ConnectionError(format!("WebSocket send error: {}", e)))?;
        
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Vec<u8>> {
        // 检查连接是否存在
        let stream = self.stream.as_mut().ok_or_else(|| {
            ClientError::ConnectionError("Not connected".to_string())
        })?;
        
        // 接收下一条消息
        match stream.next().await {
            Some(Ok(Message::Binary(encrypted_data))) => {
                debug!("Received binary message: {} bytes", encrypted_data.len());
                let deobfuscated = crypto::deobfuscate_packet(encrypted_data);
                match crypto::decrypt(&deobfuscated, &self.aes_key) {
                    Ok(plaintext) => {
                        debug!("Decrypted binary data: {} bytes", plaintext.len());
                        Ok(plaintext)
                    }
                    Err(e) => {
                        error!("Binary decryption failed: {}", e);
                        Err(ClientError::ConnectionError(format!("Decryption error: {}", e)))
                    }
                }
            }
            Some(Ok(Message::Text(text))) => {
                debug!("Received text message: {} bytes", text.len());
                // 在开启混淆的情况下，Text 帧通常是混淆后的 Base64 字符串
                let data = text.into_bytes();
                let deobfuscated = crypto::deobfuscate_packet(data);
                
                match crypto::decrypt(&deobfuscated, &self.aes_key) {
                    Ok(plaintext) => {
                        debug!("Decrypted text data: {} bytes", plaintext.len());
                        Ok(plaintext)
                    }
                    Err(_) => {
                        // 如果解密失败，可能是服务端发来的纯文本（非混淆包）
                        debug!("Text decryption failed, using raw data (debug/compat)");
                        // 还原数据并返回原文
                        Ok(deobfuscated)
                    }
                }
            }
            Some(Ok(Message::Ping(data))) => {
                debug!("Received ping, sending pong");
                // 自动响应 ping
                stream.send(Message::Pong(data)).await
                    .map_err(|e| ClientError::ConnectionError(format!("WebSocket pong error: {}", e)))?;
                // 递归调用以获取下一条实际消息
                self.receive().await
            }
            Some(Ok(Message::Pong(_))) => {
                debug!("Received pong");
                // 忽略 pong，继续接收下一条消息
                self.receive().await
            }
            Some(Ok(Message::Close(frame))) => {
                info!("Received close frame: {:?}", frame);
                // 清空连接
                self.stream = None;
                // 返回空数据表示连接关闭
                Ok(Vec::new())
            }
            Some(Ok(Message::Frame(_))) => {
                warn!("Received raw frame, ignoring");
                // 忽略原始帧，继续接收下一条消息
                self.receive().await
            }
            Some(Err(e)) => {
                error!("WebSocket error: {}", e);
                // 清空连接
                self.stream = None;
                Err(ClientError::ConnectionError(format!("WebSocket receive error: {}", e)))
            }
            None => {
                warn!("WebSocket connection closed by server");
                // 清空连接
                self.stream = None;
                // 返回空数据表示连接关闭
                Ok(Vec::new())
            }
        }
    }
    
    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_transport_creation() {
        let transport = WebSocketTransport::new("ws://127.0.0.1:8080/ws".to_string());
        assert_eq!(transport.url(), "ws://127.0.0.1:8080/ws");
        assert!(!transport.is_connected());
    }

    #[test]
    fn test_websocket_transport_url_cleaning() {
        // 测试 null 字节清理
        let transport = WebSocketTransport::new(
            "ws://192.168.1.100:8080/ws\0\0\0\0\0\0\0\0".to_string()
        );
        assert_eq!(transport.url(), "ws://192.168.1.100:8080/ws");
    }

    #[test]
    fn test_websocket_transport_url_with_leading_nulls() {
        // 测试前导 null 字节清理
        let transport = WebSocketTransport::new(
            "\0\0ws://example.com/ws\0\0".to_string()
        );
        assert_eq!(transport.url(), "ws://example.com/ws");
    }

    #[test]
    fn test_websocket_transport_url_with_whitespace() {
        // 测试空白字符清理
        let transport = WebSocketTransport::new(
            "  ws://test.local/ws   \0\0\0".to_string()
        );
        assert_eq!(transport.url(), "ws://test.local/ws");
    }

    #[test]
    fn test_websocket_transport_not_connected_initially() {
        let transport = WebSocketTransport::new("ws://127.0.0.1:8080/ws".to_string());
        assert!(!transport.is_connected());
    }
    
    // 注意：实际的连接测试需要运行中的服务器，
    // 这些测试将在集成测试中进行
}
