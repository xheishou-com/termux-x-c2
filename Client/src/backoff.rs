// 指数退避重连机制
//
// 实现指数退避算法，用于在连接失败时控制重连间隔。
// 初始延迟为 1 秒，每次失败后延迟时间翻倍，最大延迟为 60 秒。

use std::time::Duration;

/// 指数退避策略
/// 
/// 用于控制重连间隔时间，实现指数增长的延迟策略。
/// 
/// # 算法
/// 
/// - 初始延迟：1 秒
/// - 增长因子：2（每次失败后延迟时间翻倍）
/// - 最大延迟：60 秒
/// 
/// # 示例
/// 
/// ```
/// use c2_client_agent::ExponentialBackoff;
/// use std::time::Duration;
/// 
/// let mut backoff = ExponentialBackoff::new();
/// 
/// // 第一次重连：等待 1 秒
/// assert_eq!(backoff.next_delay(), Duration::from_secs(1));
/// 
/// // 第二次重连：等待 2 秒
/// assert_eq!(backoff.next_delay(), Duration::from_secs(2));
/// 
/// // 连接成功后重置
/// backoff.reset();
/// assert_eq!(backoff.next_delay(), Duration::from_secs(1));
/// ```
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// 当前延迟时间
    current_delay: Duration,
    /// 最大延迟时间
    max_delay: Duration,
    /// 增长倍数
    multiplier: u32,
}

impl ExponentialBackoff {
    /// 创建新的指数退避策略
    /// 
    /// 初始延迟为 1 秒，最大延迟为 60 秒，增长因子为 2。
    pub fn new() -> Self {
        Self {
            current_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            multiplier: 2,
        }
    }
    
    /// 获取下一次重连的延迟时间
    /// 
    /// 该方法返回当前的延迟时间，并将内部状态更新为下一次的延迟时间。
    /// 延迟时间按指数增长，直到达到最大值。
    /// 
    /// # 返回值
    /// 
    /// 返回当前应该等待的时间长度。
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.current_delay;
        
        // 计算下一次的延迟时间（当前延迟 * 倍数）
        let next = self.current_delay.as_secs() * self.multiplier as u64;
        
        // 确保不超过最大延迟
        if next >= self.max_delay.as_secs() {
            self.current_delay = self.max_delay;
        } else {
            self.current_delay = Duration::from_secs(next);
        }
        
        delay
    }
    
    /// 重置延迟时间
    /// 
    /// 将延迟时间重置为初始值（1 秒）。
    /// 通常在连接成功后调用，以便下次连接失败时从初始延迟开始。
    pub fn reset(&mut self) {
        self.current_delay = Duration::from_secs(1);
    }
    
    /// 获取当前延迟时间（不更新状态）
    /// 
    /// 该方法仅用于查看当前的延迟时间，不会修改内部状态。
    pub fn current(&self) -> Duration {
        self.current_delay
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_delay() {
        let backoff = ExponentialBackoff::new();
        assert_eq!(backoff.current(), Duration::from_secs(1));
    }

    #[test]
    fn test_exponential_growth() {
        let mut backoff = ExponentialBackoff::new();
        
        // 验证指数增长序列：1, 2, 4, 8, 16, 32, 60, 60, ...
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
        assert_eq!(backoff.next_delay(), Duration::from_secs(2));
        assert_eq!(backoff.next_delay(), Duration::from_secs(4));
        assert_eq!(backoff.next_delay(), Duration::from_secs(8));
        assert_eq!(backoff.next_delay(), Duration::from_secs(16));
        assert_eq!(backoff.next_delay(), Duration::from_secs(32));
        
        // 达到最大值后应该保持在 60 秒
        assert_eq!(backoff.next_delay(), Duration::from_secs(60));
        assert_eq!(backoff.next_delay(), Duration::from_secs(60));
        assert_eq!(backoff.next_delay(), Duration::from_secs(60));
    }

    #[test]
    fn test_max_delay_cap() {
        let mut backoff = ExponentialBackoff::new();
        
        // 多次调用 next_delay，确保不会超过最大值
        for _ in 0..20 {
            let delay = backoff.next_delay();
            assert!(delay.as_secs() <= 60);
        }
    }

    #[test]
    fn test_reset() {
        let mut backoff = ExponentialBackoff::new();
        
        // 增长到较大的延迟
        backoff.next_delay(); // 1
        backoff.next_delay(); // 2
        backoff.next_delay(); // 4
        backoff.next_delay(); // 8
        
        // 重置后应该回到初始值
        backoff.reset();
        assert_eq!(backoff.current(), Duration::from_secs(1));
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn test_reset_after_max() {
        let mut backoff = ExponentialBackoff::new();
        
        // 增长到最大值
        for _ in 0..10 {
            backoff.next_delay();
        }
        
        assert_eq!(backoff.current(), Duration::from_secs(60));
        
        // 重置后应该回到初始值
        backoff.reset();
        assert_eq!(backoff.current(), Duration::from_secs(1));
    }

    #[test]
    fn test_current_does_not_modify_state() {
        let mut backoff = ExponentialBackoff::new();
        
        // current() 不应该修改状态
        assert_eq!(backoff.current(), Duration::from_secs(1));
        assert_eq!(backoff.current(), Duration::from_secs(1));
        assert_eq!(backoff.current(), Duration::from_secs(1));
        
        // next_delay() 应该修改状态
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
        assert_eq!(backoff.current(), Duration::from_secs(2));
    }

    #[test]
    fn test_default_trait() {
        let backoff = ExponentialBackoff::default();
        assert_eq!(backoff.current(), Duration::from_secs(1));
    }

    #[test]
    fn test_delay_sequence() {
        let mut backoff = ExponentialBackoff::new();
        
        // 验证完整的延迟序列
        let expected = vec![1, 2, 4, 8, 16, 32, 60, 60, 60];
        let mut actual = Vec::new();
        
        for _ in 0..expected.len() {
            actual.push(backoff.next_delay().as_secs());
        }
        
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_multiple_resets() {
        let mut backoff = ExponentialBackoff::new();
        
        // 第一轮
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
        assert_eq!(backoff.next_delay(), Duration::from_secs(2));
        
        // 重置
        backoff.reset();
        
        // 第二轮
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
        assert_eq!(backoff.next_delay(), Duration::from_secs(2));
        
        // 再次重置
        backoff.reset();
        
        // 第三轮
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn test_clone() {
        let mut backoff1 = ExponentialBackoff::new();
        backoff1.next_delay(); // 1
        backoff1.next_delay(); // 2
        
        // 克隆应该保持相同的状态
        let backoff2 = backoff1.clone();
        assert_eq!(backoff1.current(), backoff2.current());
        assert_eq!(backoff2.current(), Duration::from_secs(4));
    }
}
