use std::{mem::size_of, os::raw::c_void};

use libbpf_sys::{bpf_map_get_fd_by_id, bpf_map_get_next_id, bpf_map_info, bpf_obj_get_info_by_fd};
use libc::{__u32, close};


#[derive(Debug)]
pub struct BpfMap {
	pub name: String,
	pub map_id: u32,
	pub map_fd: i32,
}

/// Searches for the BPF map named `map_name` in the current system.
/// The search is performed in ascending order of map IDs, and the first map
/// with a matching name is returned.
/// 
/// NOTE: Privileged access is required.
pub fn find_bpf_map_by_name(map_name: &str) -> Result<BpfMap, String>
{
	if !is_root::is_root() {
		return Err("Run me as root".to_string());
	}
	let mut map_id = 0;
	loop {
		let mut next_map_id = 0;
		let err = unsafe { bpf_map_get_next_id(map_id, &mut next_map_id as *mut __u32) };
		if err < 0 {
			return Err(format!("BPF map {map_name} not found"));
		}

		map_id = next_map_id;

		let map_fd = unsafe { bpf_map_get_fd_by_id(map_id) };
		if map_fd < 0 {
			return Err(format!("Failed to open BPF map (id={map_id})"))
		}

		let mut map_info = bpf_map_info::default();
		let mut info_len = size_of::<bpf_map_info>() as u32;
		let err = unsafe {
			bpf_obj_get_info_by_fd(
				map_fd,
				&mut map_info as *mut bpf_map_info as *mut c_void,
				&mut info_len as *mut __u32)
		};
		if err < 0 {
			unsafe { close(map_fd); }
			return Err(format!("Failed to get the information of the BPF map (id={map_id})"));
		}

		for (i, b) in map_info.name.iter().enumerate() {
			if *b == 0 {
				if map_name.as_bytes().len() == i || map_name.as_bytes()[i] == 0 {
					return Ok(BpfMap{
						name: map_name.to_string(),
						map_id,
						map_fd,
					});
				}
				break;
			}

			if map_name.as_bytes().len() <= i {
				break;
			}

			if *b as u8 != map_name.as_bytes()[i] {
				break;
			}
		}
		unsafe { close(map_fd); }
	}
}
