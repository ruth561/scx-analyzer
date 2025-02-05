const BUSY_UNIT: usize = 50000;

pub fn busy(weight: u64) -> f32
{
	let mut f = 1.001;
	for _ in 0..(weight as usize * BUSY_UNIT) {
		if f < 10000000.0 {
			f = f * f + 3.5 * f;
		} else {
			f = f - 10000000.0 * f;
		}
	}
	return f
}
