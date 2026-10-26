//! TCP connect port scanning, with no external tools.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

const MAX_PORTS: usize = 200;

/// Filled in by the "Common" button.
pub const COMMON: &str = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443";

pub fn service(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        135 => "rpc",
        139 => "netbios",
        143 => "imap",
        443 => "https",
        445 => "smb",
        993 => "imaps",
        995 => "pop3s",
        1723 => "pptp",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        5900 => "vnc",
        8080 => "http-alt",
        8443 => "https-alt",
        _ => return None,
    })
}

/// Parses `22, 80,443,8000-8010` into a sorted, de-duplicated list.
/// An empty string means "no port scan".
pub fn parse(input: &str) -> Result<Vec<u16>, String> {
    let port = |s: &str| -> Result<u16, String> {
        match s.trim().parse::<u16>() {
            Ok(p) if p > 0 => Ok(p),
            _ => Err(format!("Invalid port: {}", s.trim())),
        }
    };
    let mut out = Vec::new();
    for part in input.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (port(a)?, port(b)?);
                if b < a {
                    return Err(format!("Port range is backwards: {part}"));
                }
                out.extend(a..=b);
            }
            None => out.push(port(part)?),
        }
        if out.len() > MAX_PORTS * 4 {
            break; // avoid building a huge list just to reject it
        }
    }
    out.sort_unstable();
    out.dedup();
    if out.len() > MAX_PORTS {
        return Err(format!("Too many ports (max {MAX_PORTS})"));
    }
    Ok(out)
}

/// How long to wait for a service to talk, before and after our probe.
const READ_WAIT: Duration = Duration::from_millis(500);
/// Ports nothing listens on. If both "connect", something in the path
/// (firewall / transparent proxy) is completing handshakes for every port.
const CANARY_PORTS: [u16; 2] = [1, 61555];
const PROBE: &[u8] = b"HEAD / HTTP/1.0\r\n\r\n";

#[derive(Debug, Clone, PartialEq)]
pub enum State {
    /// The service sent data back (its banner, or a reply to our probe).
    Responded(String),
    /// The connection was accepted but nothing came back.
    Silent,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenPort {
    pub port: u16,
    pub state: State,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScanResult {
    pub open: Vec<OpenPort>,
    /// Even ports nothing listens on accepted connections.
    pub accepts_all: bool,
}

fn first_line(buf: &[u8]) -> String {
    buf.split(|&b| b == b'\r' || b == b'\n')
        .next()
        .unwrap_or(&[])
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .take(28)
        .map(|&b| b as char)
        .collect()
}

/// Connect, then check something answers: first listen for a banner (ssh,
/// smtp, ftp talk first), then send a small HTTP probe and listen again.
fn probe(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<State> {
    let mut s = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), port), timeout).ok()?;
    let _ = s.set_read_timeout(Some(READ_WAIT));
    let _ = s.set_write_timeout(Some(READ_WAIT));
    let mut buf = [0u8; 128];
    match s.read(&mut buf) {
        Ok(n) if n > 0 => return Some(State::Responded(first_line(&buf[..n]))),
        Ok(_) => return Some(State::Silent), // closed straight away
        Err(_) => {}                         // timed out: it is waiting for us
    }
    if s.write_all(PROBE).is_ok() {
        if let Ok(n) = s.read(&mut buf) {
            if n > 0 {
                return Some(State::Responded(first_line(&buf[..n])));
            }
        }
    }
    Some(State::Silent)
}

pub fn scan(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> ScanResult {
    scan_with_canary(ip, ports, timeout, &CANARY_PORTS)
}

fn scan_with_canary(ip: Ipv4Addr, ports: &[u16], timeout: Duration, canary: &[u16]) -> ScanResult {
    let mut open: Vec<OpenPort> = std::thread::scope(|s| {
        let handles: Vec<_> = ports
            .iter()
            .map(|&p| s.spawn(move || probe(ip, p, timeout).map(|state| OpenPort { port: p, state })))
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
    });
    open.sort_by_key(|o| o.port);

    let accepts_all = !open.is_empty()
        && canary.iter().all(|&c| {
            TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), c), timeout).is_ok()
        });
    if accepts_all {
        // Bare connects prove nothing here; keep only ports that really answered.
        open.retain(|o| matches!(o.state, State::Responded(_)));
    }
    ScanResult { open, accepts_all }
}

/// `22/ssh [SSH-2.0-OpenSSH_9.2], 80/http?`  (`?` = connected, sent nothing back)
pub fn format(r: &ScanResult) -> String {
    let mut parts: Vec<String> = r
        .open
        .iter()
        .map(|o| {
            let name = service(o.port).map(|n| format!("/{n}")).unwrap_or_default();
            match &o.state {
                State::Responded(line) if line.is_empty() => format!("{}{name}", o.port),
                State::Responded(line) => format!("{}{name} [{line}]", o.port),
                State::Silent => format!("{}{name}?", o.port),
            }
        })
        .collect();
    if r.accepts_all {
        parts.push(if parts.is_empty() {
            "none verified: every port accepts connections (firewall/proxy in the way)".into()
        } else {
            "(firewall accepts all ports)".into()
        });
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn parses_lists_ranges_and_dedups() {
        assert_eq!(parse("80, 22,80,8000-8002").unwrap(), vec![22, 80, 8000, 8001, 8002]);
        assert_eq!(parse("").unwrap(), Vec::<u16>::new());
        assert_eq!(parse(" , 25 ,").unwrap(), vec![25]);
    }

    #[test]
    fn common_list_is_valid() {
        assert!(parse(COMMON).unwrap().contains(&25));
    }

    #[test]
    fn rejects_bad_ports() {
        assert!(parse("abc").is_err());
        assert!(parse("0").is_err());
        assert!(parse("70000").is_err());
        assert!(parse("90-80").is_err());
        assert!(parse("1-1000").is_err()); // over the cap
    }

    fn listener(banner: Option<&'static [u8]>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for conn in l.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut c = conn;
                    if let Some(b) = banner {
                        let _ = c.write_all(b);
                    }
                    std::thread::sleep(Duration::from_secs(2)); // hold it open, say nothing more
                });
            }
        });
        port
    }

    const T: Duration = Duration::from_millis(500);

    #[test]
    fn banner_service_is_verified_and_closed_port_ignored() {
        let talks = listener(Some(b"SSH-2.0-Test\r\n"));
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port(); // dropped
        let r = scan_with_canary(Ipv4Addr::LOCALHOST, &[talks, closed], T, &[closed]);
        assert_eq!(
            r.open,
            vec![OpenPort { port: talks, state: State::Responded("SSH-2.0-Test".into()) }]
        );
        assert!(!r.accepts_all);
    }

    #[test]
    fn silent_listener_is_reported_unverified() {
        let quiet = listener(None);
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let r = scan_with_canary(Ipv4Addr::LOCALHOST, &[quiet], T, &[closed]);
        assert_eq!(r.open, vec![OpenPort { port: quiet, state: State::Silent }]);
        assert_eq!(format(&r), format!("{quiet}?"));
    }

    #[test]
    fn host_that_accepts_every_port_is_flagged_and_silent_ports_dropped() {
        // Both "canary" ports and the scanned port accept, like a filtering middlebox.
        let (a, b, quiet) = (listener(None), listener(None), listener(None));
        let r = scan_with_canary(Ipv4Addr::LOCALHOST, &[quiet], T, &[a, b]);
        assert!(r.accepts_all);
        assert!(r.open.is_empty());
        assert!(format(&r).contains("every port accepts connections"));
    }

    #[test]
    fn formats_with_service_names_and_banners() {
        let r = ScanResult {
            open: vec![
                OpenPort { port: 22, state: State::Responded("SSH-2.0-OpenSSH_9.2".into()) },
                OpenPort { port: 80, state: State::Silent },
                OpenPort { port: 9999, state: State::Responded("".into()) },
            ],
            accepts_all: false,
        };
        assert_eq!(format(&r), "22/ssh [SSH-2.0-OpenSSH_9.2], 80/http?, 9999");
    }
}
