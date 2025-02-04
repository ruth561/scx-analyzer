use std::os::raw::c_void;

use libbpf_sys::bpf_map_lookup_elem;

use crate::thread::get_errno_string;
use super::map::find_bpf_map_by_name;
use super::map::BpfMap;


const PIDFD_THREAD: u32 = 0x80;

/*
 * Wrapper function for the pidfd_open system call.
 */
pub fn pidfd_open(pid: i32, flags: u32) -> Result<i32, String>
{
	let ret;
	unsafe {
		ret = libc::syscall(libc::SYS_pidfd_open, pid, flags) as i32;
	};
	if ret < 0 {
		Err(format!("pidfd_open: errno {}", get_errno_string()))
	} else {
		Ok(ret)
	}
}

/*
 * By default, the pidfd_open system call does not accept thread IDs as the first argument.
 * However, if the PIDFD_THREAD flag is specified, it allows thread IDs.
 * This wrapper function adds the flag to the flags argument to enable this behavior.
 */
pub fn tidfd_open(tid: i32, flags: u32) -> Result<i32, String>
{
	pidfd_open(tid, flags | PIDFD_THREAD)
}

pub fn pidfd_close(pidfd: i32) -> Result<(), String>
{
	let err;
	unsafe {
		err = libc::close(pidfd);
	}
	if err < 0 {
		Err(format!("pidfd_close: errno {}", get_errno_string()))
	} else {
		Ok(())
	}
}

pub fn tidfd_close(tidfd: i32) -> Result<(), String>
{
	pidfd_close(tidfd)
}

/*
 * Structure for BPF map type `BPF_MAP_TYPE_TASK_STORAGE`.
 */
pub struct TaskStorage {
	pub bpf_map: BpfMap,
}

impl TaskStorage {
	pub fn new(map_name: &str) -> Result<TaskStorage, String>
	{
		let bpf_map = find_bpf_map_by_name(map_name)?;
		Ok(TaskStorage {
			bpf_map
		})
	}

	/*
	 * Perform bpf_map_lookup_elem for @self.
	 * The type of @value must match the element type of BPF_MAP_TYPE_TASK_STORAGE.
	 * This function overwrites @value.
	 */
	pub fn lookup_elem<T>(&self, tid: i32, value: &mut T) -> Result<(), String>
	{
		let tidfd = tidfd_open(tid, 0)?;
		let err;
		unsafe {
			err = bpf_map_lookup_elem(
				self.bpf_map.map_fd,
				&tidfd as *const i32 as *const c_void,
				value as *mut T as *mut c_void
			);
		}
		tidfd_close(tidfd)?;

		if err < 0 {
			Err(format!("lookup_elem: errno {}", get_errno_string()))
		} else {
			Ok(())
		}
	}
}

impl Drop for TaskStorage {
	fn drop(&mut self) {
		unsafe {
			libc::close(self.bpf_map.map_fd);
		}
	}
}
