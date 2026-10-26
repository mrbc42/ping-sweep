//! `portcheck 192.168.88.57 22,80,443` - same port scan the GUI uses.
#[path = "../src/ports.rs"]
mod ports;
use std::time::Duration;

fn main() {
    let (ip, list) = (std::env::args().nth(1).unwrap(), std::env::args().nth(2).unwrap());
    let r = ports::scan(ip.parse().unwrap(), &ports::parse(&list).unwrap(), Duration::from_millis(700));
    println!("{ip}: {}", if r.open.is_empty() && !r.accepts_all { "nothing open".into() } else { ports::format(&r) });
}
