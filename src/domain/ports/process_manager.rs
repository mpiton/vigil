use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    Terminate,
    Kill,
    Hangup,
    Interrupt,
    User1,
    User2,
}

#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("process not found: pid {0}")]
    NotFound(u32),
    #[error("permission denied to manage process: pid {0}")]
    PermissionDenied(u32),
    #[error("failed to send signal: {0}")]
    SignalFailed(String),
}

pub trait ProcessManager: Send + Sync {
    /// Terminate a process by PID (sends SIGKILL).
    ///
    /// # Errors
    ///
    /// Returns `ProcessError` if the process is not found,
    /// permission is denied, or the signal fails.
    fn kill(&self, pid: u32) -> Result<(), ProcessError>;

    /// Send a specific signal to a process.
    ///
    /// # Errors
    ///
    /// Returns `ProcessError` if the process is not found,
    /// permission is denied, or the signal fails.
    fn signal(&self, pid: u32, signal: Signal) -> Result<(), ProcessError>;
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn process_error_display() {
        let err = ProcessError::NotFound(1234);
        assert_eq!(err.to_string(), "process not found: pid 1234");

        let err = ProcessError::PermissionDenied(5678);
        assert_eq!(
            err.to_string(),
            "permission denied to manage process: pid 5678"
        );

        let err = ProcessError::SignalFailed("SIGTERM failed".to_string());
        assert_eq!(err.to_string(), "failed to send signal: SIGTERM failed");
    }
}
