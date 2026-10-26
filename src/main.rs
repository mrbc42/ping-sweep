mod icmp;
mod network;
mod ports;

use std::cell::{Cell, RefCell};
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use slint::{ModelExt, Timer, TimerMode, VecModel};

slint::include_modules!();

const MAX_HOSTS: u64 = 4096;
const WORKERS: usize = 64;
const TIMEOUT: Duration = Duration::from_secs(2);
const PORT_TIMEOUT: Duration = Duration::from_millis(700);

/// Accepts `a.b.c.d`, `a.b.c.d/len`, `a.b.c.d-e.f.g.h` and `a.b.c.d-N`
/// (N replaces the last octet).
fn parse_range(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    let input = input.trim();
    let bad = |s: &str| format!("Invalid address: {s}");
    let (start, end) = if let Some((net, len)) = input.split_once('/') {
        let base: Ipv4Addr = net.trim().parse().map_err(|_| bad(net))?;
        let len: u32 = len.trim().parse().map_err(|_| bad(len))?;
        if len > 32 {
            return Err("Prefix length must be 0-32".into());
        }
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        let (first, last) = (u32::from(base) & mask, u32::from(base) | !mask);
        // Skip network and broadcast addresses on normal subnets.
        if len < 31 {
            (first + 1, last - 1)
        } else {
            (first, last)
        }
    } else if let Some((a, b)) = input.split_once('-') {
        let a: Ipv4Addr = a.trim().parse().map_err(|_| bad(a))?;
        let end = if b.contains('.') {
            u32::from(b.trim().parse::<Ipv4Addr>().map_err(|_| bad(b))?)
        } else {
            let last: u8 = b.trim().parse().map_err(|_| bad(b))?;
            (u32::from(a) & !0xff) | last as u32
        };
        (u32::from(a), end)
    } else {
        let a: Ipv4Addr = input.parse().map_err(|_| bad(input))?;
        (u32::from(a), u32::from(a))
    };
    if end < start {
        return Err("Range end is before its start".into());
    }
    if (end - start) as u64 + 1 > MAX_HOSTS {
        return Err(format!("Range too large (max {MAX_HOSTS} hosts)"));
    }
    Ok((start..=end).map(Ipv4Addr::from).collect())
}

struct Reply {
    ip: Ipv4Addr,
    rtt_ms: Option<f32>,
    scan: ports::ScanResult,
}

/// State of the scan in progress; lives on the UI thread.
struct Scan {
    rx: Receiver<Reply>,
    stop: Arc<AtomicBool>,
    total: usize,
    done: usize,
    alive: usize,
    keys: Vec<u32>, // sorted address keys, parallel to the model rows
}

fn spawn_workers(hosts: Vec<Ipv4Addr>, ports: Vec<u16>, stop: Arc<AtomicBool>) -> Receiver<Reply> {
    let (tx, rx) = mpsc::channel();
    let (hosts, ports) = (Arc::new(hosts), Arc::new(ports));
    let next = Arc::new(AtomicUsize::new(0));
    for _ in 0..WORKERS.min(hosts.len()) {
        let (tx, hosts, ports, next, stop) =
            (tx.clone(), hosts.clone(), ports.clone(), next.clone(), stop.clone());
        thread::spawn(move || loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            if i >= hosts.len() || stop.load(Ordering::Relaxed) {
                break;
            }
            let rtt_ms = icmp::ping(hosts[i], TIMEOUT).unwrap_or(None);
            // Only hosts that answered the ping get a port scan.
            let scan = if rtt_ms.is_some() && !ports.is_empty() {
                ports::scan(hosts[i], &ports, PORT_TIMEOUT)
            } else {
                ports::ScanResult::default()
            };
            if tx.send(Reply { ip: hosts[i], rtt_ms, scan }).is_err() {
                break;
            }
        });
    }
    rx // channel disconnects once every worker has exited
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;
    ui.set_version(env!("CARGO_PKG_VERSION").into());

    match network::detect() {
        Some(c) => {
            ui.set_range(c.cidr.clone().into());
            let others = match c.others {
                0 => String::new(),
                n => format!(" ({n} other network{} ignored)", if n == 1 { "" } else { "s" }),
            };
            ui.set_summary(format!("Detected {} on {}{others}. Press Scan.", c.ip, c.name).into());
        }
        None => ui.set_summary("Could not detect your network; enter a range and press Scan.".into()),
    }

    let model = Rc::new(VecModel::<HostResult>::default());
    let filter = Rc::new(Cell::new(0));
    let filtered = Rc::new(model.clone().filter({
        let filter = filter.clone();
        move |r| match filter.get() {
            1 => r.alive,
            2 => !r.alive,
            _ => true,
        }
    }));
    ui.set_results(filtered.clone().into());
    let scan: Rc<RefCell<Option<Scan>>> = Rc::new(RefCell::new(None));

    ui.on_start({
        let (ui, model, scan) = (ui.as_weak(), model.clone(), scan.clone());
        move |range, ports| {
            let ui = ui.unwrap();
            if scan.borrow().is_some() {
                return;
            }
            let hosts = match parse_range(&range) {
                Ok(h) => h,
                Err(e) => return ui.set_summary(e.into()),
            };
            let ports = match ports::parse(&ports) {
                Ok(p) => p,
                Err(e) => return ui.set_summary(e.into()),
            };
            if let Err(e) = icmp::check_access() {
                return ui.set_summary(e.into());
            }
            model.set_vec(Vec::new());
            let stop = Arc::new(AtomicBool::new(false));
            *scan.borrow_mut() = Some(Scan {
                total: hosts.len(),
                rx: spawn_workers(hosts, ports, stop.clone()),
                stop,
                done: 0,
                alive: 0,
                keys: Vec::new(),
            });
            ui.set_progress(0.0);
            ui.set_alive_count(0);
            ui.set_dead_count(0);
            ui.set_summary("Scanning…".into());
            ui.set_scanning(true);
        }
    });

    ui.on_set_filter({
        let ui = ui.as_weak();
        move |f| {
            filter.set(f);
            filtered.reset();
            ui.unwrap().set_filter(f);
        }
    });

    ui.on_common_ports({
        let ui = ui.as_weak();
        move || ui.unwrap().set_ports(ports::COMMON.into())
    });

    ui.on_stop({
        let scan = scan.clone();
        move || {
            if let Some(s) = scan.borrow().as_ref() {
                s.stop.store(true, Ordering::Relaxed);
            }
        }
    });

    // Drain worker results on the UI thread; keeps the model single-threaded.
    let timer = Timer::default();
    timer.start(TimerMode::Repeated, Duration::from_millis(50), {
        let (ui, model, scan) = (ui.as_weak(), model.clone(), scan.clone());
        move || {
            let ui = ui.unwrap();
            let mut guard = scan.borrow_mut();
            let Some(s) = guard.as_mut() else { return };
            let mut finished = false;
            loop {
                match s.rx.try_recv() {
                    Ok(r) => {
                        s.done += 1;
                        s.alive += r.rtt_ms.is_some() as usize;
                        let key = u32::from(r.ip);
                        let pos = s.keys.partition_point(|k| *k < key);
                        s.keys.insert(pos, key);
                        model.insert(
                            pos,
                            HostResult {
                                ip: r.ip.to_string().into(),
                                alive: r.rtt_ms.is_some(),
                                ports: ports::format(&r.scan).into(),
                                rtt: r.rtt_ms.map(|ms| format!("{ms:.1} ms")).unwrap_or_default().into(),
                            },
                        );
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        finished = true;
                        break;
                    }
                }
            }
            ui.set_progress(s.done as f32 / s.total as f32);
            ui.set_alive_count(s.alive as i32);
            ui.set_dead_count((s.done - s.alive) as i32);
            let status = if finished {
                if s.done < s.total { "Stopped" } else { "Done" }
            } else {
                "Scanning…"
            };
            ui.set_summary(
                format!("{status} — {} alive, {} no reply, {}/{} checked",
                    s.alive, s.done - s.alive, s.done, s.total).into(),
            );
            if finished {
                ui.set_scanning(false);
                *guard = None;
            }
        }
    });

    ui.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_skips_network_and_broadcast() {
        let h = parse_range("192.168.1.0/24").unwrap();
        assert_eq!(h.len(), 254);
        assert_eq!(h[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(h[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn short_and_full_dash_ranges() {
        assert_eq!(parse_range("10.0.0.5-8").unwrap().len(), 4);
        assert_eq!(parse_range("10.0.0.250-10.0.1.2").unwrap().len(), 9);
    }

    #[test]
    fn single_host() {
        assert_eq!(parse_range(" 8.8.8.8 ").unwrap(), vec![Ipv4Addr::new(8, 8, 8, 8)]);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_range("nope").is_err());
        assert!(parse_range("10.0.0.9-2").is_err());
        assert!(parse_range("10.0.0.0/8").is_err()); // too large
        assert!(parse_range("10.0.0.0/33").is_err());
    }
}
