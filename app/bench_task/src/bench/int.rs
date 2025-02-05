const BUSY_UNIT: usize = 50000;

pub fn busy(weight: u64)
{
	for i in 0..(weight as usize * BUSY_UNIT) {
		std::hint::black_box(i);
	}
}
