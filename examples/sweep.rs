//! Headless sweep using the same ICMP code as the GUI: `sweep 192.168.88 [workers]`
#[path = "../src/icmp.rs"]
mod icmp;

use std::net::Ipv4Addr;
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex};
use std::time::Duration;

fn main() {
    let prefix = std::env::args().nth(1).expect("usage: sweep A.B.C [workers]");
    let workers: usize = std::env::args().nth(2).and_then(|w| w.parse().ok()).unwrap_or(64);
    icmp::check_access().unwrap();
    let next = Arc::new(AtomicUsize::new(1));
    let alive = Arc::new(Mutex::new(Vec::new()));
    let hs: Vec<_> = (0..workers).map(|_| {
        let (next, alive, prefix) = (next.clone(), alive.clone(), prefix.clone());
        std::thread::spawn(move || loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            if i > 254 { break; }
            let ip: Ipv4Addr = format!("{prefix}.{i}").parse().unwrap();
            if let Ok(Some(ms)) = icmp::ping(ip, Duration::from_secs(1)) {
                alive.lock().unwrap().push((i, ms));
            }
        })
    }).collect();
    for h in hs { h.join().unwrap(); }
    let mut a = alive.lock().unwrap().clone();
    a.sort_by_key(|x| x.0);
    println!("{} alive: {}", a.len(), a.iter().map(|(i, ms)| format!(".{i}({ms:.0}ms)")).collect::<Vec<_>>().join(" "));
}
