# The diverter

Source: `nucleus/crates/diverter/src/`. Off by default; `[diverter] enabled = true` turns it
on, and only inside the analysis VM.

```{warning}
The diverter redirects; it doesn't block. Some traffic still leaves, and stopping the
nucleus removes the diversion; outbound traffic stays blocked until `--restore-network` (`block_after_stop`: Linux keeps its iptables block; Windows installs a firewall block on stop, and a guard process installs it if the nucleus dies). See flaw LEAK-02.
```

## The plan

`Config::plan` (in the CLI) turns the listeners into a `Plan`: `tcp_ports` and `udp_ports`
(fixed listeners keep their port), `tcp_default` and `udp_default` (the first `auto`
listener of each transport), `passive_ports` (the FTP range) and `ignore_ports`.

## Linux (`linux.rs`)

`rules(config, plan, family)` generates these commands (unit-tested verbatim), for
iptables and, if `ipv6`, ip6tables:

```text
-t nat -N FAKENET
-t nat -A FAKENET -m addrtype --dst-type LOCAL -j RETURN      single host
-t nat -A FAKENET -d 127.0.0.0/8 -j RETURN                     gateway (::1/128 for v6)
-t nat -A FAKENET -m mark --mark 0x4b1d/0x4b1d -j RETURN       with excluded_processes
-t nat -A FAKENET -p tcp|udp --dport P -j RETURN               each ignore_ports entry
-t nat -A FAKENET -p icmp --icmp-type echo-request -j REDIRECT answer_ping (ipv6-icmp for v6)
-t nat -A FAKENET -p tcp --dport P -j REDIRECT --to-ports P    fixed TCP listeners
-t nat -A FAKENET -p tcp --dport A:B -j REDIRECT               FTP passive range
-t nat -A FAKENET -p udp --dport P -j REDIRECT --to-ports P    fixed UDP listeners
-t nat -A FAKENET -p tcp -j REDIRECT --to-ports <auto tcp>
-t nat -A FAKENET -p udp -j REDIRECT --to-ports <auto udp>
-t nat -I OUTPUT|PREROUTING -j FAKENET
-t mangle -N FAKENET                                           with excluded_processes:
-t mangle -A FAKENET -p tcp|udp -m addrtype ! --dst-type LOCAL -m conntrack --ctstate NEW \
         -j NFQUEUE --queue-num N --queue-bypass
-t mangle -I OUTPUT -j FAKENET
```

- `Active::start` first cleans up leftovers, then applies IPv4 (an error is fatal) and IPv6
  (an error is a warning). It runs `iptables -w` so it waits for the xtables lock.
- `start_queue`: a non-blocking NFQUEUE loop. For each new connection's first packet it
  parses the addresses, finds the owning process (`find_process`) and sets the mark if the
  `comm` name is excluded. The verdict is always accept; `--queue-bypass` accepts packets
  if the queue isn't running.
- `cleanup`: deletes the jumps (up to 8 times each, for duplicates left by crashes), then
  flushes and deletes both chains, for both families. `--restore-network` runs it.
- The kernel does the NAT. Listeners recover original destinations with `SO_ORIGINAL_DST`
  and `IP_ORIGDSTADDR`.

## Windows (`windows.rs`, `reflect.rs`, `host_settings.rs`)

WinDivert can't NAT, so packets are reflected:

- **Single host**: a client packet `S:sp → D:dp` is re-injected inbound as `D:sp → S:L`
  (L = the listener port). The reply `S:L → D:sp` goes out as `D:dp → S:sp`.
- **Gateway**: a forwarded `C:cp → D:dp` becomes `C:cp → G:L`, and the reply goes out as
  `D:dp → C:cp`.
- UDP from a non-listener port opens an alias flow (TFTP transfer IDs). Only a SYN starts a
  TCP flow. Flows idle for 600 s expire; at most 65,536 are kept.

`reflect::Reflector` holds this state and is pure (unit-tested on Linux).
`Reflector::original` gives listeners the real client, destination and process
(`Context.original`).

`windows.rs` opens three WinDivert handles: the socket layer (sniff, to map
`(transport, local port)` to a PID), the network layer
(`outbound and !loopback and (tcp or udp[ or icmp])`), and in gateway mode the forward
layer. `reflect_outbound` answers pings itself, waits up to 2 ms for the owner when
exclusions are configured, skips its own PID and excluded image names, then rewrites
(`packet::rewrite`) and re-injects. Optional FakeNet-NG-style host changes
(`fix_dns`, `fix_gateway`) are applied with generated PowerShell and restored on stop. The
handles close when the process exits.

This code type-checks for Windows but has not been run in CI (flaw ARCH-01).

## Packets (`packet.rs`)

`parse` (IPv4 without non-first fragments and with IHL ≥ 5, or IPv6 without extension
headers; TCP or UDP; SYN and FIN flags), `rewrite` (same family; recomputes the IPv4
header checksum and the TCP/UDP checksum; a UDP checksum of 0 becomes 0xffff),
`echo_reply` (ICMP and ICMPv6).

## Wire capture (`wire.rs`)

`WireCapture::start(sink)`. Linux: an AF_PACKET `SOCK_DGRAM` socket with a 200 ms receive
timeout, IPv4 and IPv6 only, skipping loopback duplicates. Windows: a WinDivert sniff
handle. Dropping it stops the thread (on Windows the thread isn't joined, because it blocks
until the next packet).

## Windows containment

| When | What blocks | Source |
|---|---|---|
| Running | With `block_undiverted`, WinDivert sees every outbound packet (single host) or forwarded packet (gateway); `reflect::drops` drops what isn't diverted or exempt (`ignore_ports`, excluded processes), except link-local control traffic (`packet::is_link_local_control`: IGMP, 224.0.0.0/24, IPv6 link-local and `ff02::/16`) | `windows.rs` `reflect_outbound`, `reflect_forwarded` |
| Stopping | With `block_after_stop`, a Windows Firewall rule group `FakeNet hybrid` blocks outbound traffic to every address but loopback (block rules win over allow rules); the firewall is switched on for every profile and IP forwarding off. The previous state goes to `%ProgramData%\FakeNetHybrid\block-state.json` | `host_settings::install_block_script` |
| Crashing | A detached guard (`fakenet-nucleus --block-after-exit PID`, started with the diversion, outside the task's job when allowed) waits for the nucleus to exit, however it exits, then installs the same block | `windows::guard_exit`, `main.rs` `start_exit_guard` |
| Released | `--restore-network` removes the rule group and restores the saved profile and forwarding state. The next start does it too, once WinDivert is in place | `host_settings::release_block_script` |

The firewall decides on a connection before WinDivert sees its packets, which is why the
block can't simply stay on while diverting: the start lifts it only after its own blocking
(WinDivert) runs.
