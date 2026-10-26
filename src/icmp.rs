//! Minimal in-process ICMPv4 echo, so the app does not depend on a system `ping`.
//!
//! Tries an unprivileged datagram ICMP socket first (Linux when
//! `net.ipv4.ping_group_range` covers the user, and macOS), then falls back to
//! a raw socket (needs root / CAP_NET_RAW).

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;

static SEQ: AtomicU16 = AtomicU16::new(1);

fn open() -> io::Result<Socket> {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
        .or_else(|_| Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)))
}

/// Check up front that an ICMP socket can be opened, with a helpful message.
pub fn check_access() -> Result<(), String> {
    open().map(|_| ()).map_err(|e| {
        format!(
            "Cannot open an ICMP socket ({e}). On Linux run: \
             sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\""
        )
    })
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_request(id: u16, seq: u16) -> Vec<u8> {
    let mut p = vec![0u8; 16];
    p[0] = ECHO_REQUEST;
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6..8].copy_from_slice(&seq.to_be_bytes());
    p[8..].copy_from_slice(b"pingswp!");
    let c = checksum(&p);
    p[2..4].copy_from_slice(&c.to_be_bytes());
    p
}

/// Returns `(id, seq)` if `buf` is an echo reply. Raw sockets (and macOS
/// datagram sockets) deliver the IP header too; Linux datagram sockets don't.
fn parse_reply(buf: &[u8]) -> Option<(u16, u16)> {
    let icmp = if buf.first().map(|b| b >> 4) == Some(4) {
        buf.get(((buf[0] & 0x0f) as usize) * 4..)?
    } else {
        buf
    };
    if icmp.len() < 8 || icmp[0] != ECHO_REPLY {
        return None;
    }
    Some((
        u16::from_be_bytes([icmp[4], icmp[5]]),
        u16::from_be_bytes([icmp[6], icmp[7]]),
    ))
}

/// Send one echo request and wait up to `timeout` for the reply.
/// `Ok(Some(rtt_ms))` = alive, `Ok(None)` = no reply, `Err` = socket failure.
pub fn ping(ip: Ipv4Addr, timeout: Duration) -> io::Result<Option<f32>> {
    let sock = open()?;
    // Connected sockets only receive replies from this host.
    sock.connect(&SockAddr::from(SocketAddrV4::new(ip, 0)))?;

    let id = std::process::id() as u16;
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let start = Instant::now();
    (&sock).write_all(&build_request(id, seq))?;

    let mut buf = [0u8; 256];
    loop {
        let left = timeout.saturating_sub(start.elapsed());
        if left.is_zero() {
            return Ok(None);
        }
        sock.set_read_timeout(Some(left))?;
        match (&sock).read(&mut buf) {
            Ok(n) => {
                // Linux datagram sockets rewrite the id, so only check seq there.
                if let Some((_, rseq)) = parse_reply(&buf[..n]) {
                    if rseq == seq {
                        return Ok(Some(start.elapsed().as_secs_f32() * 1000.0));
                    }
                }
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                return Ok(None)
            }
            // Unreachable / refused notifications from the connected socket.
            Err(_) => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_valid_packet_is_zero() {
        let p = build_request(0x1234, 7);
        assert_eq!(checksum(&p), 0);
    }

    #[test]
    fn parses_bare_and_ip_wrapped_replies() {
        let mut icmp = build_request(1, 42);
        icmp[0] = ECHO_REPLY;
        assert_eq!(parse_reply(&icmp), Some((1, 42)));

        let mut wrapped = vec![0x45u8, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1];
        wrapped.extend_from_slice(&icmp);
        assert_eq!(parse_reply(&wrapped), Some((1, 42)));
    }

    #[test]
    fn ignores_requests() {
        assert_eq!(parse_reply(&build_request(1, 1)), None);
    }

    #[test]
    fn loopback_is_alive() {
        // Skipped where the sandbox forbids ICMP sockets.
        if let Err(e) = check_access() {
            eprintln!("SKIPPED: {e}");
            return;
        }
        assert!(ping(Ipv4Addr::LOCALHOST, Duration::from_secs(1)).unwrap().is_some());
    }
}
