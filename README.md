##MCprobe

High-performance Minecraft server scanner and protocol prober.

Scans servers using the native Minecraft protocol to collect:
- MOTD and favicon
- Version and protocol
- Player counts and sample players
- Authentication mode (online, offline, whitelist)

Designed for speed and scale using async Rust (Tokio).
Handles compression, protocol differences (1.8+), and timeouts.

Input:
- input.txt (one ip per line, IP[:PORT] if not port is provided will use deafult 25565)

Output:
- results.json (structured scan results)

Usage:
cargo run --release

Disclaimer:
Users are responsible for ensuring compliance with local laws and regulations.
