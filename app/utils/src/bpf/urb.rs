use std::mem::size_of;

use libbpf_sys::user_ring_buffer;
use libbpf_sys::user_ring_buffer__free;
use libbpf_sys::user_ring_buffer__new;
use libbpf_sys::user_ring_buffer__reserve;
use libbpf_sys::user_ring_buffer__submit;

use super::map::find_bpf_map_by_name;
use super::map::BpfMap;


/// Structure for BPF map type `BPF_MAP_TYPE_USER_RINGBUF`.
/// This BPF map used to send variable-length messages from userspace
/// to the BPF side. You must have privileged access to use it.
pub struct UserRingBuffer {
	pub bpf_map: BpfMap,
	urb_ptr: *mut user_ring_buffer,
}

impl UserRingBuffer {
	/// Creates a `UserRingBuffer` instance using `map_name`.
	/// You must ensure that the BPF map exists.
	/// This constructor searches for the map in the current system,
	/// opens it, and creates a `user_ring_buffer` instance as defined
	/// on the libbpf side. 
	pub fn new(map_name: &str) -> Result<UserRingBuffer, String> {
		println!("UserRingBuffer::new()");
		let bpf_map = find_bpf_map_by_name(map_name)?;
		println!("UserRingBuffer::new(): bpf_map: {:?}", bpf_map);
		let urb_ptr = unsafe {
			let urb_ptr = user_ring_buffer__new(bpf_map.map_fd, std::ptr::null());
			if urb_ptr.is_null() {
				return Err("Failed to create user ring buffer".to_string());
			}
			urb_ptr
		};
		Ok(UserRingBuffer {
			bpf_map,
			urb_ptr,
		})
	}

	/// Sends the message `msg` via the `UserRingBuffer`.
	pub fn send<T>(&mut self, msg: T) -> Result<(), String> {
		let msg_len = size_of::<T>() as u32;
		unsafe {
			let buf_ptr = user_ring_buffer__reserve(self.urb_ptr, msg_len);
			if buf_ptr.is_null() {
				return Err("Failed to reserve urb buffer".to_string());
			}
			*(buf_ptr as *mut T) = msg;
			user_ring_buffer__submit(self.urb_ptr, buf_ptr);
		}
		Ok(())
	}
}

impl Drop for UserRingBuffer {
	fn drop(&mut self) {
		unsafe {
			user_ring_buffer__free(self.urb_ptr);
			libc::close(self.bpf_map.map_fd);
		}
	}
}
