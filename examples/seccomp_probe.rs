//! Small integration probe proving that the Software Shield seccomp filter is active.
//! It reads the kernel's own process status and tries PTRACE_TRACEME in this short-lived child.
use std::{fs, io, process};

fn main() {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(status) => status,
        Err(error) => {
            eprintln!("FAIL: cannot read /proc/self/status: {error}");
            process::exit(10);
        }
    };
    let seccomp = status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp:").map(str::trim));
    if seccomp != Some("2") {
        eprintln!("FAIL: expected Seccomp: 2, got {:?}", seccomp);
        process::exit(11);
    }
    println!("PASS: kernel reports Seccomp: 2 (filter mode).");

    // PTRACE_TRACEME only affects this short-lived test process. The policy must reject it.
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
        println!("PASS: ptrace syscall denied with EPERM by seccomp policy.");
        return;
    }
    if result == 0 {
        eprintln!("FAIL: PTRACE_TRACEME unexpectedly succeeded; seccomp denylist is not enforced.");
    } else {
        eprintln!(
            "FAIL: ptrace returned unexpected error: {}",
            io::Error::last_os_error()
        );
    }
    process::exit(12);
}
