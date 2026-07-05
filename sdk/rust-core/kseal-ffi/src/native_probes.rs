//! OS-specific native anti-debug / anti-Frida probes.
//!
//! These feed the existing `DEBUGGER` (bit 4) and `HOOKING` (bit 5) risk
//! signals from a native code path that is independent of — and deeper than —
//! the Kotlin/Swift heuristics. Running the check in the shared Rust core makes
//! it harder for an attacker to neutralise by hooking the managed layer alone.
//!
//! ## Invariants
//!
//! - **Post-launch only / cheap.** Every entry point is side-effect-free and
//!   repeatable: it reads `/proc` (Linux/Android) or queries `sysctl` / `dyld`
//!   (Darwin). In particular it deliberately does **not** call
//!   `ptrace(PTRACE_TRACEME)` / `ptrace(PT_DENY_ATTACH)` — those have
//!   irreversible, one-shot side effects and are unsuitable for a check that
//!   runs on every trust evaluation.
//! - **Fail-safe.** A check that cannot run (unsupported platform, unreadable
//!   OS surface) returns [`UNAVAILABLE`]; the SDK treats anything other than
//!   [`PRESENT`] as "no signal", so a native check can never *raise* a false
//!   positive.
//!
//! The pure parsing helpers are platform-independent and unit-tested with
//! synthetic input; the platform entry points read the real OS surface and
//! delegate to them.

/// A debugger/tracer or instrumentation framework was positively detected.
pub(crate) const PRESENT: i32 = 1;
/// The check ran and observed nothing suspicious.
pub(crate) const CLEAN: i32 = 0;
/// The check could not run on this platform / the OS surface was unreadable.
/// Treated as "no signal" by every caller (fail-safe).
pub(crate) const UNAVAILABLE: i32 = -1;

// ---------------------------------------------------------------------------
// Pure, platform-independent helpers (always compiled; unit-tested directly).
// ---------------------------------------------------------------------------

/// Parses the `TracerPid:` field from `/proc/self/status` content. Returns the
/// tracer PID, or `0` when the field is absent / unparseable (i.e. no tracer).
#[allow(dead_code)] // used on Linux/Android; referenced by tests elsewhere.
pub(crate) fn tracer_pid_from_status(status: &str) -> i32 {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("TracerPid:") {
            return rest.trim().parse::<i32>().unwrap_or(0);
        }
    }
    0
}

/// Substrings that betray an injected instrumentation library when present in
/// `/proc/self/maps` (Linux/Android) or a loaded image path (Darwin).
const HOOK_MARKERS: [&str; 8] = [
    "frida",
    "frida-agent",
    "frida-gadget",
    "libgadget",
    "xposed",
    "substrate",
    "libsubstrate",
    "cynject",
];

/// Whether a single `/proc/self/maps` line or loaded-image path names a known
/// instrumentation library.
pub(crate) fn line_has_hook_marker(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    HOOK_MARKERS.iter().any(|m| lower.contains(m))
}

/// Whether any line of a `/proc/self/maps` dump names an instrumentation
/// library.
#[allow(dead_code)] // used on Linux/Android.
pub(crate) fn maps_contains_hook(maps: &str) -> bool {
    maps.lines().any(line_has_hook_marker)
}

/// Frida spawns helper threads with recognisable `comm` names — most notably
/// the Gum runtime loop (`gum-js-loop`). Whether a thread name matches. Kept
/// deliberately specific so ordinary app threads can never trip it.
#[allow(dead_code)] // used on Linux/Android.
pub(crate) fn thread_name_is_suspicious(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower.contains("frida") || lower.contains("gum-js-loop")
}

// ---------------------------------------------------------------------------
// Platform entry points.
// ---------------------------------------------------------------------------

/// Linux / Android: read `TracerPid` from `/proc/self/status`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn debugger_present() -> i32 {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(status) => {
            if tracer_pid_from_status(&status) > 0 {
                PRESENT
            } else {
                CLEAN
            }
        }
        Err(_) => UNAVAILABLE,
    }
}

/// Linux / Android: scan `/proc/self/maps` for an injected instrumentation
/// library, then scan thread names (`/proc/self/task/<tid>/comm`) for Frida's
/// helper threads.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn hook_present() -> i32 {
    let mut read_ok = false;

    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        read_ok = true;
        if maps_contains_hook(&maps) {
            return PRESENT;
        }
    }

    if let Ok(entries) = std::fs::read_dir("/proc/self/task") {
        for entry in entries.flatten() {
            if let Ok(name) = std::fs::read_to_string(entry.path().join("comm")) {
                read_ok = true;
                if thread_name_is_suspicious(&name) {
                    return PRESENT;
                }
            }
        }
    }

    if read_ok {
        CLEAN
    } else {
        UNAVAILABLE
    }
}

/// `P_TRACED` flag from `<sys/proc.h>` — not exported by the `libc` crate.
#[cfg(any(target_os = "macos", target_os = "ios"))]
const P_TRACED: i32 = 0x10;

/// Minimal `#[repr(C)]` mirror of `struct kinfo_proc` — only the prefix up to
/// `kp_proc.p_flag` is needed; the rest is opaque padding. The `libc` crate
/// does not export this type on Darwin.
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[repr(C)]
struct KinfoProc {
    // struct extern_proc kp_proc:
    //   union { struct proc *p_forw, *p_back; } p_un — 16 bytes on 64-bit
    p_un: [u8; 16],
    //   struct vmspace *p_vmspace — 8 bytes
    p_vmspace: *mut libc::c_void,
    //   struct sigacts *p_sigacts — 8 bytes
    p_sigacts: *mut libc::c_void,
    //   int p_flag
    p_flag: i32,
    // remaining fields are opaque
}

/// Darwin (macOS / iOS): test the `P_TRACED` flag via `sysctl(KERN_PROC)`.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn debugger_present() -> i32 {
    // Safety: `info` is fully owned and sized; `sysctl` writes at most
    // `size` bytes into it and reports the real length back.
    unsafe {
        let mut info: KinfoProc = std::mem::zeroed();
        let mut size = std::mem::size_of::<KinfoProc>();
        let mut mib: [libc::c_int; 4] = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_PID,
            libc::getpid(),
        ];
        let rc = libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            &mut info as *mut _ as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        if rc != 0 {
            return UNAVAILABLE;
        }
        if (info.p_flag & P_TRACED) != 0 {
            PRESENT
        } else {
            CLEAN
        }
    }
}

/// Darwin (macOS / iOS): scan the loaded dyld images for an injected
/// instrumentation library (Frida gadget, Cydia Substrate, …).
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn hook_present() -> i32 {
    extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_name(image_index: u32) -> *const libc::c_char;
    }
    // Safety: the dyld image table is process-global; indices `0..count` are
    // valid and each name pointer is a NUL-terminated C string owned by dyld.
    unsafe {
        let count = _dyld_image_count();
        for i in 0..count {
            let name_ptr = _dyld_get_image_name(i);
            if name_ptr.is_null() {
                continue;
            }
            if let Ok(name) = std::ffi::CStr::from_ptr(name_ptr).to_str() {
                if line_has_hook_marker(name) {
                    return PRESENT;
                }
            }
        }
    }
    CLEAN
}

/// Any other platform: the native checks are unavailable, so they contribute no
/// signal.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
pub(crate) fn debugger_present() -> i32 {
    UNAVAILABLE
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
pub(crate) fn hook_present() -> i32 {
    UNAVAILABLE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracer_pid_parses_attached_tracer() {
        let status = "Name:\tapp\nState:\tt (tracing stop)\nTracerPid:\t2451\nUid:\t0\n";
        assert_eq!(tracer_pid_from_status(status), 2451);
    }

    #[test]
    fn tracer_pid_zero_when_not_traced() {
        let status = "Name:\tapp\nTracerPid:\t0\nUid:\t0\n";
        assert_eq!(tracer_pid_from_status(status), 0);
    }

    #[test]
    fn tracer_pid_zero_when_absent() {
        assert_eq!(tracer_pid_from_status("Name:\tapp\nUid:\t0\n"), 0);
    }

    #[test]
    fn maps_flags_frida_agent() {
        let maps = "\
7f0000000000-7f0000001000 r-xp 00000000 fd:00 1 /system/lib64/libc.so
7f0000002000-7f0000003000 r-xp 00000000 fd:00 9 /data/local/tmp/re.frida.server/frida-agent-64.so
";
        assert!(maps_contains_hook(maps));
    }

    #[test]
    fn maps_flags_substrate() {
        let maps = "7f00-7f01 r-xp 0 fd:00 9 /usr/lib/libsubstrate.dylib\n";
        assert!(maps_contains_hook(maps));
    }

    #[test]
    fn clean_maps_are_silent() {
        let maps = "\
7f0000000000-7f0000001000 r-xp 00000000 fd:00 1 /system/lib64/libc.so
7f0000002000-7f0000003000 r-xp 00000000 fd:00 2 /system/lib64/libart.so
";
        assert!(!maps_contains_hook(maps));
    }

    #[test]
    fn frida_thread_names_are_suspicious() {
        assert!(thread_name_is_suspicious("gum-js-loop\n"));
        assert!(thread_name_is_suspicious("frida-server\n"));
        assert!(thread_name_is_suspicious("pool-frida"));
    }

    #[test]
    fn ordinary_thread_names_are_clean() {
        for name in ["app", "RenderThread", "Binder:1234_2", "gmain", "FinalizerDaemon"] {
            assert!(!thread_name_is_suspicious(name), "{name} should be clean");
        }
    }
}
