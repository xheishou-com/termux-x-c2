// PTY (伪终端) 处理模块
//
// 当服务器通过 Yamux 发起新流时，在客户端生成一个交互式终端（PTY）
// 并将输入输出通过 Yamux 流进行双向传输

use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use std::io::{Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use log::{debug, error, info, warn};

/// 处理服务器发起的 Yamux 流，生成 PTY 会话
/// 
/// # 参数
/// 
/// * `stream` - Yamux 流，用于与服务器通信
/// 
/// # 工作流程
/// 
/// 1. 初始化 PTY 系统
/// 2. 创建伪终端对（master/slave）
/// 3. 在 slave 端启动 shell（Windows: cmd.exe, Linux: /bin/bash）
/// 4. 建立双向数据管道：
///    - PTY Master -> Yamux Stream (终端输出发送到服务器)
///    - Yamux Stream -> PTY Master (服务器命令写入终端)
pub async fn handle_stream(stream: yamux::Stream) {
    info!("[PTY] Starting PTY session for new Yamux stream");
    
    // 1. 初始化 PTY 系统
    let pty_system = NativePtySystem::default();
    
    // 2. 创建 PTY，设置标准终端大小
    let pair = match pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    }) {
        Ok(p) => {
            debug!("[PTY] PTY pair created successfully");
            p
        }
        Err(e) => {
            error!("[PTY] Failed to create PTY: {}", e);
            return;
        }
    };
    
    // 3. 根据操作系统选择 shell
    let cmd = if cfg!(target_os = "windows") {
        debug!("[PTY] Spawning cmd.exe for Windows");
        CommandBuilder::new("cmd.exe")
    } else {
        debug!("[PTY] Spawning /bin/bash for Unix-like system");
        CommandBuilder::new("/bin/bash")
    };
    
    // 在 slave 端启动 shell 进程
    let mut child = match pair.slave.spawn_command(cmd) {
        Ok(c) => {
            info!("[PTY] Shell process spawned successfully");
            c
        }
        Err(e) => {
            error!("[PTY] Failed to spawn shell: {}", e);
            return;
        }
    };
    
    // 4. 获取 PTY master 的读写句柄
    let mut reader = match pair.master.try_clone_reader() {
        Ok(r) => r,
        Err(e) => {
            error!("[PTY] Failed to clone PTY reader: {}", e);
            return;
        }
    };
    
    let mut writer = match pair.master.take_writer() {
        Ok(w) => w,
        Err(e) => {
            error!("[PTY] Failed to take PTY writer: {}", e);
            return;
        }
    };
    
    // 5. 将 Yamux Stream 转换为 Tokio 兼容的异步流
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    let (mut r_stream, mut w_stream) = tokio::io::split(stream.compat());
    
    // 6. 创建通道用于在阻塞和异步任务之间传递数据
    let (tx_to_yamux, mut rx_to_yamux) = mpsc::channel::<Vec<u8>>(100);
    let (tx_to_pty, mut rx_to_pty) = mpsc::channel::<Vec<u8>>(100);
    
    // 任务 1: PTY -> Yamux (阻塞读取 -> 异步发送)
    // 在阻塞线程中读取 PTY 输出，通过通道发送给异步任务
    tokio::task::spawn_blocking(move || {
        let mut buffer = [0u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    debug!("[PTY->Yamux] PTY reader EOF");
                    break;
                }
                Ok(n) => {
                    debug!("[PTY->Yamux] Read {} bytes from PTY", n);
                    let data = buffer[..n].to_vec();
                    if tx_to_yamux.blocking_send(data).is_err() {
                        warn!("[PTY->Yamux] Channel closed, stopping PTY reader");
                        break;
                    }
                }
                Err(e) => {
                    error!("[PTY->Yamux] PTY read error: {}", e);
                    break;
                }
            }
        }
        debug!("[PTY->Yamux] PTY reader thread terminated");
    });
    
    // 任务 2: 从通道接收 PTY 数据并写入 Yamux 流
    let yamux_writer = tokio::spawn(async move {
        while let Some(data) = rx_to_yamux.recv().await {
            if let Err(e) = w_stream.write_all(&data).await {
                error!("[PTY->Yamux] Failed to write to Yamux stream: {}", e);
                break;
            }
            if let Err(e) = w_stream.flush().await {
                error!("[PTY->Yamux] Failed to flush Yamux stream: {}", e);
                break;
            }
            debug!("[PTY->Yamux] Sent {} bytes to Yamux", data.len());
        }
        debug!("[PTY->Yamux] Yamux writer task terminated");
    });
    
    // 任务 3: Yamux -> PTY (异步读取 -> 阻塞写入)
    // 从 Yamux 流读取数据，通过通道发送给阻塞写入任务
    let yamux_reader = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        loop {
            match r_stream.read(&mut buffer).await {
                Ok(0) => {
                    debug!("[Yamux->PTY] Yamux stream EOF");
                    break;
                }
                Ok(n) => {
                    debug!("[Yamux->PTY] Read {} bytes from Yamux", n);
                    let data = buffer[..n].to_vec();
                    if tx_to_pty.send(data).await.is_err() {
                        warn!("[Yamux->PTY] Channel closed, stopping Yamux reader");
                        break;
                    }
                }
                Err(e) => {
                    error!("[Yamux->PTY] Yamux read error: {}", e);
                    break;
                }
            }
        }
        debug!("[Yamux->PTY] Yamux reader task terminated");
    });
    
    // 任务 4: 从通道接收 Yamux 数据并写入 PTY
    let pty_writer = tokio::task::spawn_blocking(move || {
        while let Some(data) = rx_to_pty.blocking_recv() {
            if let Err(e) = writer.write_all(&data) {
                error!("[Yamux->PTY] Failed to write to PTY: {}", e);
                break;
            }
            if let Err(e) = writer.flush() {
                error!("[Yamux->PTY] Failed to flush PTY: {}", e);
                break;
            }
            debug!("[Yamux->PTY] Wrote {} bytes to PTY", data.len());
        }
        debug!("[Yamux->PTY] PTY writer thread terminated");
    });
    
    info!("[PTY] All data pipes established, PTY session active");
    
    // 等待所有任务完成（任何一个结束都意味着会话结束）
    tokio::select! {
        _ = yamux_writer => {
            debug!("[PTY] Yamux writer finished");
        }
        _ = yamux_reader => {
            debug!("[PTY] Yamux reader finished");
        }
        _ = pty_writer => {
            debug!("[PTY] PTY writer finished");
        }
    }
    
    // 清理：终止 shell 进程
    match child.wait() {
        Ok(status) => {
            info!("[PTY] Shell process exited with status: {:?}", status);
        }
        Err(e) => {
            warn!("[PTY] Failed to wait for shell process: {}", e);
        }
    }
    
    info!("[PTY] PTY session terminated");
}
