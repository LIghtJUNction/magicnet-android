//! Startup uses a private pipe and a temporary direct parent for the core.
//! That parent keeps the core waitable through the final group signal. A dead
//! controller closes the pipe; a readiness byte transfers the live core.

use super::{
    defer_child_reap, sanitize_cli_child_environment, terminate_timed_out_child,
    DEFAULT_COMMAND_TIMEOUT_SECS,
};
use crate::App;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const START_TIMEOUT: Duration = Duration::from_secs(DEFAULT_COMMAND_TIMEOUT_SECS);
const STOP_GRACE: Duration = Duration::from_secs(10);
const GUARD_FD: libc::c_int = 8;

pub(crate) fn launch_singbox(app: &App) -> Result<(), String> {
    let ready = readiness_pipe()?;
    let guard = inherited_startup_guard(app)?;
    let mut command = Command::new(
        std::env::current_exe().map_err(|err| format!("core launcher executable: {err}"))?,
    );
    command
        .arg("__singbox-launch-worker")
        .env("MODDIR", &app.moddir)
        .env_remove("MAGICNET_COMMAND_TIMEOUT")
        .stdin(Stdio::piped())
        .stdout(Stdio::null());
    sanitize_cli_child_environment(&mut command);
    let parent = unsafe { libc::getpid() };
    let guard_fd = guard.as_raw_fd();
    // Only this private worker inherits the locked open-file description. It
    // leaves the controller group before exec, so group timeout becomes pipe
    // EOF and cannot kill the owner before it finishes core rollback.
    unsafe {
        command.pre_exec(move || {
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            if libc::setsid() == -1
                || libc::dup2(guard_fd, GUARD_FD) == -1
                || libc::fcntl(GUARD_FD, libc::F_SETFD, 0) == -1
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let _budget = crate::utils::reserve_child_probe()?;
    let mut worker = command
        .spawn()
        .map_err(|err| format!("start core launcher: {err}"))?;
    let mut control = worker
        .stdin
        .take()
        .ok_or("core launcher pipe is unavailable")?;
    let result = wait_for_ready(&worker, &ready, START_TIMEOUT).and_then(|()| {
        control
            .write_all(b"R")
            .map_err(|err| format!("core handoff: {err}"))
    });
    drop(control);
    let deadline = Instant::now() + STOP_GRACE + Duration::from_secs(1);
    loop {
        if let Some(status) = worker
            .try_wait()
            .map_err(|err| format!("wait core launcher: {err}"))?
        {
            return result.and_then(|()| {
                if status.success() {
                    Ok(())
                } else {
                    Err("core startup handoff failed".to_string())
                }
            });
        }
        if Instant::now() >= deadline {
            // The worker still owns the guard and cleanup. Killing it here
            // would recreate the orphan/second-writer race we are avoiding.
            defer_child_reap(worker);
            return Err("core startup rollback is still in progress".to_string());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub(crate) fn launch_singbox_worker(app: &App) -> Result<(), String> {
    let ready = readiness_pipe()?;
    let _guard = inherited_startup_guard(app)?;
    fs::create_dir_all(&app.log_dir).map_err(|err| format!("core log directory: {err}"))?;
    let log = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(app.log_dir.join("sing-box.log"))
        .map_err(|err| format!("core log: {err}"))?;
    if !log
        .metadata()
        .map_err(|err| format!("core log: {err}"))?
        .is_file()
    {
        return Err("core log is not a regular file".to_string());
    }
    let mut command = Command::new(app.moddir.join("bin/sing-box"));
    command
        .arg("run")
        .arg("-c")
        .arg(app.moddir.join(".config/sing-box/config.json"))
        .arg("-D")
        .arg(app.moddir.join(".config/sing-box"))
        .env("MODDIR", &app.moddir)
        .env_remove("MAGICNET_COMMAND_TIMEOUT")
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(|err| format!("core log: {err}"))?)
        .stderr(log);
    sanitize_cli_child_environment(&mut command);
    // This process is the core's wait owner until handoff. Its private pipe
    // detects controller/launcher death without relying on a recycled PID.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 || libc::signal(libc::SIGHUP, libc::SIG_IGN) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let _budget = crate::utils::reserve_child_probe()?;
    let mut child = command
        .spawn()
        .map_err(|err| format!("start core: {err}"))?;
    let result = wait_for_ready(&child, &ready, START_TIMEOUT);
    if result.is_err() {
        // Do not reap before signalling the group: the waitable child pins its
        // PID/PGID even if the leader exits while a descendant ignores TERM.
        terminate_timed_out_child(&mut child, STOP_GRACE, Duration::from_millis(100));
        // A kernel-stuck child cannot be reported as cleaned up. Keep this
        // guard-owning worker until it really exits; the outer launcher has
        // its own bounded wait and reports pending cleanup to the controller.
        child
            .wait()
            .map_err(|err| format!("wait for core rollback: {err}"))?;
    }
    result
}

fn readiness_pipe() -> Result<File, String> {
    let pipe = File::from(
        io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|err| format!("readiness pipe: {err}"))?,
    );
    if !pipe
        .metadata()
        .map_err(|err| format!("readiness pipe: {err}"))?
        .file_type()
        .is_fifo()
    {
        return Err("sing-box launch requires a readiness pipe".to_string());
    }
    Ok(pipe)
}

fn inherited_startup_guard(app: &App) -> Result<File, String> {
    // The shell takes the metadata guard before forking a launcher. Reopening
    // it here would create a dead-owner/reacquisition gap. All copies refer to
    // the same flock; no process explicitly unlocks it while another owns it.
    let fd = unsafe { libc::fcntl(GUARD_FD, libc::F_DUPFD_CLOEXEC, 3) };
    if fd == -1 {
        return Err("core startup guard was not inherited".to_string());
    }
    let guard = unsafe { File::from_raw_fd(fd) };
    let inherited = guard
        .metadata()
        .map_err(|err| format!("startup guard: {err}"))?;
    let expected = fs::symlink_metadata(app.moddir.join(".state/config.lock.guard"))
        .map_err(|err| format!("startup guard path: {err}"))?;
    if !inherited.is_file()
        || !expected.is_file()
        || inherited.dev() != expected.dev()
        || inherited.ino() != expected.ino()
    {
        return Err("invalid core startup guard".to_string());
    }
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == -1 {
        return Err("core startup guard is not owned".to_string());
    }
    Ok(guard)
}

fn wait_for_ready(child: &Child, mut ready: &File, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if crate::utils::peek_child_status(child.id() as libc::pid_t)
            .map_err(|err| format!("inspect starting service: {err}"))?
            .is_some()
        {
            return Err("service exited before readiness".to_string());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("sing-box readiness deadline expired".to_string());
        }
        let mut event = libc::pollfd {
            fd: ready.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let status =
            unsafe { libc::poll(&mut event, 1, remaining.as_millis().clamp(1, 100) as i32) };
        if status < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("readiness pipe: {err}"));
        }
        if status == 0 {
            continue;
        }
        if event.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("sing-box readiness pipe failed".to_string());
        }
        let mut marker = [0_u8; 1];
        match ready.read(&mut marker) {
            Ok(1) if marker[0] == b'R' => {
                return match crate::utils::peek_child_status(child.id() as libc::pid_t) {
                    Ok(None) => Ok(()),
                    Ok(Some(_)) => Err("service exited before handoff".to_string()),
                    Err(err) => Err(format!("inspect ready service: {err}")),
                };
            }
            Ok(0) => return Err("sing-box controller closed before readiness".to_string()),
            Ok(_) => return Err("invalid sing-box readiness acknowledgement".to_string()),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(format!("readiness pipe: {err}")),
        }
    }
}
