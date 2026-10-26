//! Picks the default scan range from the host's own addresses.
//!
//! Candidates are the IPv4 addresses of the local interfaces. Virtual,
//! tunnel and container interfaces and CGNAT/VPN ranges are penalised, private
//! (RFC 1918) LAN addresses are preferred, and the address the OS would use
//! for its default route gets a bonus.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};

#[derive(Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
}

#[derive(Debug, PartialEq)]
pub struct Choice {
    pub cidr: String,
    pub ip: Ipv4Addr,
    pub name: String,
    /// Other usable networks that were not chosen.
    pub others: usize,
}

/// Ranges wider than /22 (> 1022 hosts) are narrowed to the host's /24.
const WIDEST_PREFIX: u32 = 22;

const VIRTUAL_PREFIXES: &[&str] = &[
    "lo", "docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "podman", "cni", "flannel",
    "cali", "tun", "tap", "wg", "tailscale", "zt", "utun", "netwarden", "ham", "vethernet",
];

fn is_virtual(name: &str) -> bool {
    let n = name.to_lowercase();
    VIRTUAL_PREFIXES.iter().any(|p| n.starts_with(p))
        || ["virtualbox", "vmware", "hyper-v", "wsl", "loopback"].iter().any(|p| n.contains(p))
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..128).contains(&o[1])
}

fn score(i: &Iface, primary: Option<Ipv4Addr>) -> i32 {
    let mut s = 0;
    if i.ip.is_private() {
        s += 100;
    }
    if is_cgnat(i.ip) {
        s -= 50;
    }
    if is_virtual(&i.name) {
        s -= 200;
    }
    if Some(i.ip) == primary {
        s += 60;
    }
    s
}

fn usable(i: &Iface) -> bool {
    !(i.ip.is_loopback() || i.ip.is_link_local() || i.ip.is_unspecified() || i.ip.is_multicast())
        && i.mask != Ipv4Addr::BROADCAST // a /32 has no neighbours to scan
        && i.mask != Ipv4Addr::UNSPECIFIED
}

pub fn choose(ifaces: &[Iface], primary: Option<Ipv4Addr>) -> Option<Choice> {
    let mut cands: Vec<&Iface> = ifaces.iter().filter(|i| usable(i)).collect();
    // Stable sort, highest score first; ties keep the OS's interface order.
    cands.sort_by_key(|i| -score(i, primary));
    let best = *cands.first()?;

    let mut prefix = u32::from(best.mask).count_ones();
    if prefix < WIDEST_PREFIX {
        prefix = 24;
    }
    let mask = u32::MAX << (32 - prefix);
    let net = Ipv4Addr::from(u32::from(best.ip) & mask);
    Some(Choice {
        cidr: format!("{net}/{prefix}"),
        ip: best.ip,
        name: best.name.clone(),
        others: cands.len() - 1,
    })
}

fn local_ifaces() -> Vec<Iface> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => Some(Iface { name: i.name, ip: v4.ip, mask: v4.netmask }),
            _ => None,
        })
        .collect()
}

/// The source address the OS would use to reach the internet. Connecting a UDP
/// socket only selects a route; nothing is sent.
fn primary_ip() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v) => Some(v),
        _ => None,
    }
}

pub fn detect() -> Option<Choice> {
    choose(&local_ifaces(), primary_ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nic(name: &str, ip: [u8; 4], prefix: u32) -> Iface {
        Iface {
            name: name.into(),
            ip: Ipv4Addr::from(ip),
            mask: Ipv4Addr::from(u32::MAX << (32 - prefix)),
        }
    }

    #[test]
    fn prefers_the_real_lan_over_virtual_and_cgnat() {
        let ifs = [
            nic("lo", [127, 0, 0, 1], 8),
            nic("docker0", [172, 17, 0, 1], 16),
            nic("netwarden0", [100, 127, 255, 2], 29),
            nic("wlp2s0", [192, 168, 88, 196], 24),
        ];
        let c = choose(&ifs, Some(Ipv4Addr::new(192, 168, 88, 196))).unwrap();
        assert_eq!(c.cidr, "192.168.88.0/24");
        assert_eq!(c.name, "wlp2s0");
        assert_eq!(c.others, 2);
    }

    #[test]
    fn full_tunnel_vpn_default_route_does_not_win() {
        let ifs = [nic("wg0", [10, 8, 0, 2], 24), nic("eth0", [192, 168, 1, 20], 24)];
        let c = choose(&ifs, Some(Ipv4Addr::new(10, 8, 0, 2))).unwrap();
        assert_eq!(c.name, "eth0");
    }

    #[test]
    fn default_route_breaks_a_tie_between_two_lans() {
        let ifs = [nic("eth0", [192, 168, 1, 20], 24), nic("wlan0", [10, 0, 0, 7], 24)];
        let c = choose(&ifs, Some(Ipv4Addr::new(10, 0, 0, 7))).unwrap();
        assert_eq!(c.cidr, "10.0.0.0/24");
    }

    #[test]
    fn huge_networks_narrow_to_slash_24_and_small_ones_stay() {
        let big = choose(&[nic("eth0", [10, 20, 30, 40], 8)], None).unwrap();
        assert_eq!(big.cidr, "10.20.30.0/24");
        let small = choose(&[nic("eth0", [192, 168, 4, 77], 28)], None).unwrap();
        assert_eq!(small.cidr, "192.168.4.64/28");
    }

    #[test]
    fn nothing_usable_gives_none() {
        let ifs = [nic("lo", [127, 0, 0, 1], 8), nic("eth0", [169, 254, 1, 1], 16)];
        assert_eq!(choose(&ifs, None), None);
    }

    #[test]
    fn detect_on_this_machine() {
        eprintln!("detected: {:?}", detect());
    }
}
