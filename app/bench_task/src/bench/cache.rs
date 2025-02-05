const BUSY_UNIT: usize = 50000;

pub fn busy(weight: u64, buf: &mut [u64]) -> u64
{
	let mut acc = 0;
	for i in 2..(weight as usize * BUSY_UNIT) {
		buf[i] = (buf[i - 1] + buf[i - 2]) & 0xFFFFFFFF;
		acc += buf[i];
	}
	acc
}
