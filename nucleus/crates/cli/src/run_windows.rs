//! Windows `--run`: the sample in a Job Object (its whole process tree is tracked and dies
//! with the job; nothing can break away, since the job doesn't allow it) and, by default,
//! with a restricted token: the Administrators group deny-only, every privilege but
//! SeChangeNotify removed, medium integrity. It then can't close the WinDivert handles, change
//! the firewall, kill the nucleus or read the link secret (ACL: SYSTEM and Administrators).
//! The process starts suspended and only runs once it is in the job.

use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, STILL_ACTIVE};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, CreateWellKnownSid, GetLengthSid, SetTokenInformation, TokenIntegrityLevel, WinBuiltinAdministratorsSid, WinMediumLabelSid, DISABLE_MAX_PRIVILEGE,
    SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, ResumeThread, TerminateProcess, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_INFORMATION, STARTUPINFOW,
};

/// A handle closed on drop
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a handle this module opened and nothing else closes
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn last_error(what: &str) -> std::io::Error {
    // SAFETY: GetLastError has no preconditions
    let code = unsafe { GetLastError() };
    std::io::Error::other(format!("{what}: {}", std::io::Error::from_raw_os_error(code as i32)))
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

/// The sample's process and the job holding its tree
pub struct JobProcess {
    job: Owned,
    process: Owned,
    pub pid: u32,
}

// SAFETY: kernel handles may be used from any thread
unsafe impl Send for JobProcess {}
unsafe impl Sync for JobProcess {}

/// A well-known SID in a buffer of its own
fn well_known_sid(kind: i32) -> std::io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; 68]; // SECURITY_MAX_SID_SIZE
    let mut size = buffer.len() as u32;
    // SAFETY: `buffer` is writable for `size` bytes; no domain SID is needed for these kinds
    if unsafe { CreateWellKnownSid(kind, std::ptr::null_mut(), buffer.as_mut_ptr().cast(), &mut size) } == 0 {
        return Err(last_error("CreateWellKnownSid"));
    }
    buffer.truncate(size as usize);
    Ok(buffer)
}

/// This process's token, restricted: Administrators deny-only, privileges removed, medium
/// integrity
fn restricted_token() -> std::io::Result<Owned> {
    let mut own: HANDLE = std::ptr::null_mut();
    let access = TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
    // SAFETY: the pseudo-handle of the current process; `own` receives a token handle
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut own) } == 0 {
        return Err(last_error("OpenProcessToken"));
    }
    let own = Owned(own);
    let mut administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
    let disable = SID_AND_ATTRIBUTES { Sid: administrators.as_mut_ptr().cast(), Attributes: 0 };
    let mut restricted: HANDLE = std::ptr::null_mut();
    // SAFETY: one SID to disable, valid for the call; no privileges listed (DISABLE_MAX_PRIVILEGE
    // removes them all but SeChangeNotify) and no restricting SIDs
    if unsafe { CreateRestrictedToken(own.0, DISABLE_MAX_PRIVILEGE, 1, &disable, 0, std::ptr::null(), 0, std::ptr::null(), &mut restricted) } == 0 {
        return Err(last_error("CreateRestrictedToken"));
    }
    let restricted = Owned(restricted);
    let mut medium = well_known_sid(WinMediumLabelSid)?;
    let label = TOKEN_MANDATORY_LABEL { Label: SID_AND_ATTRIBUTES { Sid: medium.as_mut_ptr().cast(), Attributes: SE_GROUP_INTEGRITY as u32 } };
    // SAFETY: `label` and the SID it points to live for the call; the size covers both
    let size = std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + unsafe { GetLengthSid(medium.as_mut_ptr().cast()) };
    // SAFETY: as above, on the token just created
    if unsafe { SetTokenInformation(restricted.0, TokenIntegrityLevel, (&label as *const TOKEN_MANDATORY_LABEL).cast(), size) } == 0 {
        return Err(last_error("SetTokenInformation (integrity level)"));
    }
    Ok(restricted)
}

/// Starts `path` (suspended), puts it in a new kill-on-close job, then lets it run
pub fn spawn(path: &Path, args: &[String], dir: Option<&Path>, restricted: bool) -> std::io::Result<JobProcess> {
    // SAFETY: an anonymous job with default security
    let job = Owned(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) });
    if job.0.is_null() {
        return Err(last_error("CreateJobObjectW"));
    }
    // SAFETY: a zeroed limit structure is valid; only the flag is set
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `limits` is valid for its size
    if unsafe { SetInformationJobObject(job.0, JobObjectExtendedLimitInformation, (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(), std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32) } == 0 {
        return Err(last_error("SetInformationJobObject"));
    }
    let application = wide(path.as_os_str());
    let mut command_line = wide(std::ffi::OsStr::new(&crate::run::windows_command_line(&path.display().to_string(), args)));
    let directory = dir.map(|d| wide(d.as_os_str()));
    let directory_ptr = directory.as_ref().map_or(std::ptr::null(), |d| d.as_ptr());
    // SAFETY: zeroed STARTUPINFOW/PROCESS_INFORMATION are valid inputs once `cb` is set
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    let created = match restricted {
        true => {
            let token = restricted_token()?;
            // SAFETY: NUL-terminated wide strings that outlive the call, a mutable command
            // line buffer, no inherited handles, the environment of this process
            unsafe { CreateProcessAsUserW(token.0, application.as_ptr(), command_line.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 0, flags, std::ptr::null(), directory_ptr, &startup, &mut info) }
        }
        // SAFETY: as above, with this process's own token
        false => unsafe { CreateProcessW(application.as_ptr(), command_line.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 0, flags, std::ptr::null(), directory_ptr, &startup, &mut info) },
    };
    if created == 0 {
        return Err(last_error(if restricted { "CreateProcessAsUserW" } else { "CreateProcessW" }));
    }
    let process = Owned(info.hProcess);
    let thread = Owned(info.hThread);
    // SAFETY: both handles were just returned by CreateProcess*
    if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
        let error = last_error("AssignProcessToJobObject");
        // SAFETY: the suspended process we created
        unsafe { TerminateProcess(process.0, 1) };
        return Err(error);
    }
    // SAFETY: the primary thread of the suspended process
    if unsafe { ResumeThread(thread.0) } == u32::MAX {
        return Err(last_error("ResumeThread"));
    }
    Ok(JobProcess { job, process, pid: info.dwProcessId })
}

impl JobProcess {
    /// The sample's own exit code, once it has exited
    pub fn exit_code(&self) -> Option<u32> {
        let mut code = 0u32;
        // SAFETY: our process handle; `code` is writable
        if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 || code == STILL_ACTIVE as u32 {
            return None;
        }
        Some(code)
    }

    /// Processes of the tree still running
    pub fn active(&self) -> u32 {
        // SAFETY: a zeroed accounting structure is a valid output buffer
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is writable for its size
        let ok = unsafe {
            QueryInformationJobObject(self.job.0, JobObjectBasicAccountingInformation, (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(), std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32, std::ptr::null_mut())
        };
        if ok == 0 {
            return 0;
        }
        info.ActiveProcesses
    }

    /// Kills the whole tree; returns how many processes were running
    pub fn kill(&self) -> u32 {
        let running = self.active();
        // SAFETY: our job handle
        unsafe { TerminateJobObject(self.job.0, 1) };
        running
    }
}

impl Drop for JobProcess {
    fn drop(&mut self) {
        // Kill-on-close would do it when the handle closes; explicit, in case of a duplicate
        // SAFETY: our job handle
        unsafe { TerminateJobObject(self.job.0, 1) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn cmd() -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var("ComSpec").unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".into()))
    }

    fn wait_exit(process: &JobProcess) -> u32 {
        let started = Instant::now();
        loop {
            if let Some(code) = process.exit_code() {
                return code;
            }
            assert!(started.elapsed() < Duration::from_secs(20), "the process didn't exit");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn runs_with_and_without_the_restricted_token() {
        for restricted in [false, true] {
            let process = spawn(&cmd(), &["/c".into(), "exit 7".into()], None, restricted).unwrap();
            assert_eq!(wait_exit(&process), 7, "restricted: {restricted}");
        }
    }

    #[test]
    fn the_restricted_token_has_no_administrators_group() {
        // `whoami /groups` marks a deny-only group "Group used for deny only"; findstr's
        // exit code says whether Administrators (S-1-5-32-544) is enabled
        let script = "whoami /groups /fo csv | findstr /c:\"S-1-5-32-544\" | findstr /v /c:\"deny only\" >nul";
        let process = spawn(&cmd(), &["/c".into(), script.into()], None, true).unwrap();
        assert_ne!(wait_exit(&process), 0, "Administrators is still enabled in the restricted token");
    }

    #[test]
    fn killing_the_job_takes_the_whole_tree() {
        // cmd starts a grandchild (ping) and exits: the job still holds the grandchild
        let process = spawn(&cmd(), &["/c".into(), "start /b ping -n 30 127.0.0.1 >nul".into()], None, false).unwrap();
        wait_exit(&process);
        let started = Instant::now();
        while process.active() == 0 && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(process.active() >= 1, "the grandchild should still be in the job");
        assert!(process.kill() >= 1);
        let started = Instant::now();
        while process.active() > 0 && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(process.active(), 0);
    }
}
