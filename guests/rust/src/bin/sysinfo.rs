//! Exercises common runtime services: heap, time, randomness, uname.
use std::collections::HashMap;
use std::time::{Instant, SystemTime};

fn main() {
    let mut map = HashMap::new();
    for i in 0..10_000u32 {
        map.insert(i, vec![i as u8; (i % 64) as usize]);
    }
    let total: usize = map.values().map(Vec::len).sum();
    println!("heap ok: {} entries, {total} bytes", map.len());

    let start = Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let elapsed = start.elapsed().as_millis();
    println!("sleep ok: {}", elapsed >= 20);

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    println!("clock ok: {}", now.as_secs() > 1_700_000_000);

    let big = vec![0xabu8; 64 << 20];
    println!("large allocation ok: {}", big.iter().all(|&b| b == 0xab));
}
