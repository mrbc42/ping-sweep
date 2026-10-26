# Ping Sweep

A small desktop app (Rust + [Slint](https://slint.dev)) that pings an IPv4 range and shows which hosts are alive, with an optional TCP port scan.

It is self-contained: ICMP echo and the port scan are built in, so it does not use the system `ping`.

## Features

- Scan range is filled in from your own network (ignores docker, VPN and loopback interfaces).
- Accepts `192.168.1.0/24`, `10.0.0.1-10.0.0.50`, `192.168.1.1-254` or a single IP.
- Filter buttons: **All**, **Responding**, **No reply**, each with a count.
- Optional port scan: type ports (`22,80,443`, ranges like `8000-8010`) or press **Common**.
  Ports are scanned on hosts that answer the ping.
- Open ports are verified. `22/ssh [SSH-2.0-OpenSSH_9.2]` means the service answered;
  `80/http?` means it connected but said nothing. If a firewall or proxy accepts every
  port, the host is flagged and only ports that really answered are listed.

## Build and run

    cargo run --release

On Linux you need `libfontconfig1-dev` and `libxkbcommon-dev`.

## Permissions

Pings use an unprivileged ICMP socket (Linux, macOS), falling back to a raw socket (root).
If Linux refuses, run once:

    sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"

Windows is not supported yet (it needs a different ping API).

## Notes

- If a scan finds far fewer hosts than expected, a local firewall or endpoint filter may be
  dropping replies. Try from another machine on the same network.
- `examples/sweep.rs` and `examples/portcheck.rs` are headless versions of the ping and
  port-scan code for testing without a display.

## License

MIT, see [LICENSE](LICENSE). The app is built with [Slint](https://slint.dev), which has its
own license terms (GPLv3, royalty-free, or commercial) that apply to built binaries.
