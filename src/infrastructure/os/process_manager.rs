use nix::sys::signal::{self, Signal as NixSignal};
use nix::unistd::Pid;

use crate::domain::ports::process_manager::{ProcessError, ProcessManager, Signal};

/// OS-level process manager using POSIX signals via `nix`.
pub struct OsProcessManager;

impl OsProcessManager {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for OsProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

const fn to_nix_signal(sig: Signal) -> NixSignal {
    match sig {
        Signal::Terminate => NixSignal::SIGTERM,
        Signal::Kill => NixSignal::SIGKILL,
        Signal::Hangup => NixSignal::SIGHUP,
        Signal::Interrupt => NixSignal::SIGINT,
        Signal::User1 => NixSignal::SIGUSR1,
        Signal::User2 => NixSignal::SIGUSR2,
    }
}

impl ProcessManager for OsProcessManager {
    fn kill(&self, pid: u32) -> Result<(), ProcessError> {
        self.signal(pid, Signal::Kill)
    }

    fn signal(&self, pid: u32, signal: Signal) -> Result<(), ProcessError> {
        // PID 0 sends signal to the entire process group — reject it.
        if pid == 0 {
            return Err(ProcessError::SignalFailed(
                "cannot signal PID 0 (process group)".into(),
            ));
        }
        let nix_pid = Pid::from_raw(
            i32::try_from(pid)
                .map_err(|_| ProcessError::SignalFailed(format!("invalid pid: {pid}")))?,
        );
        let nix_signal = to_nix_signal(signal);

        signal::kill(nix_pid, nix_signal).map_err(|errno| match errno {
            nix::errno::Errno::ESRCH => ProcessError::NotFound(pid),
            nix::errno::Errno::EPERM => ProcessError::PermissionDenied(pid),
            other => ProcessError::SignalFailed(other.to_string()),
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn to_nix_signal_mapping() {
        assert_eq!(to_nix_signal(Signal::Terminate), NixSignal::SIGTERM);
        assert_eq!(to_nix_signal(Signal::Kill), NixSignal::SIGKILL);
        assert_eq!(to_nix_signal(Signal::Hangup), NixSignal::SIGHUP);
        assert_eq!(to_nix_signal(Signal::Interrupt), NixSignal::SIGINT);
        assert_eq!(to_nix_signal(Signal::User1), NixSignal::SIGUSR1);
        assert_eq!(to_nix_signal(Signal::User2), NixSignal::SIGUSR2);
    }

    #[test]
    fn kill_nonexistent_process() {
        let manager = OsProcessManager::new();
        // PID 0 would be kernel, use a very unlikely PID
        let result = manager.signal(4_194_300, Signal::Terminate);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ProcessError::NotFound(_) | ProcessError::PermissionDenied(_))
        ));
    }

    #[test]
    fn signal_pid_zero_is_rejected() {
        let manager = OsProcessManager::new();
        let result = manager.signal(0, Signal::Terminate);
        assert!(result.is_err());
        assert!(matches!(result, Err(ProcessError::SignalFailed(_))));
    }

    #[test]
    #[allow(clippy::default_constructed_unit_structs)]
    fn default_creates_instance() {
        let _manager = OsProcessManager::default();
    }
}
