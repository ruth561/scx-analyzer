use std::thread;
use std::ffi::CStr;
use std::thread::ThreadId;

/// scheduling policy defined in linux kernel uapi header
#[allow(unused)]
const SCHED_OTHER: i32 = 0;
const SCHED_EXT: i32 = 7;

/// This is like std::thread 
pub struct ExtThread {
	pub tid: ThreadId,
	handle: thread::JoinHandle<()>,
}

impl ExtThread {
	/// This function is similar to std::thread::spawn.
	/// The difference is that the spwaned thread has `SCHED_EXT`
	/// scheduling policy.
	pub fn spawn<F>(f: F) -> ExtThread
	where
		F: FnOnce() + Send + 'static,
	{
		let handle = std::thread::spawn(move || {
			set_ext_policy(0).unwrap();
			f();
		});

		ExtThread {
			tid: handle.thread().id(),
			handle,
		}
	}

	pub fn join(self) {
		self.handle.join().unwrap()
	}
}

fn get_errno() -> i32 {
	unsafe { *libc::__errno_location() }
}

fn get_errno_string() -> String {
	unsafe {
		let c_str = libc::strerror(get_errno());
		if c_str.is_null() {
			"Unknown error".to_string()
		} else {
			CStr::from_ptr(c_str).to_string_lossy().into_owned()
		}
	}
}

/// Retrieves the scheduling policy of the task specified by `tid`.
/// To retrieve the policy of the current thread, set `tid` to 0.
/// 
/// Returns the policy if successful, or a string describing the error if it fails.
pub fn get_sched_policy(tid: i32) -> Result<i32, String> {
	let policy = unsafe { libc::sched_getscheduler(tid) };
	if policy >= 0 {
		Ok(policy)
	} else {
		Err(get_errno_string())
	}
}

fn set_sched_param(tid: i32, policy: i32, priority: i32) -> Result<(), String> {
	let param = libc::sched_param { sched_priority: priority };
	let err = unsafe { libc::sched_setscheduler(tid, policy, &param) };
	if err == 0 {
	    Ok(())
	} else {
	    Err(get_errno_string())
	}
}

/// Sets the `SCHED_EXT` policy for the thread specified by `tid`.
/// To apply the policy to the current thread, set `tid`.to 0.
///
/// Returns a string describing the error if it fails.
pub fn set_ext_policy(tid: i32) -> Result<(), String>
{
	set_sched_param(tid, SCHED_EXT, 0)
}

#[test]
fn test() {
	let et = ExtThread::spawn(|| {
		assert_eq!(SCHED_EXT, get_sched_policy(0).unwrap())
	});
	et.join();
}
