# Diverter (`nucleus/crates/diverter/src`)

## `lib.rs`

| Item | Role |
|---|---|
| `DiverterConfig`, `Mode::{SingleHost, Gateway}` | See [config.md](config.md#diverter-diverterdiverterconfig) |
| `Plan { tcp_ports, udp_ports, tcp_default, udp_default, passive_ports, ignore_ports }` | Built by `Config::plan` |
| `Diverter::start(config, plan)` | Linux or Windows backend. Fails on other operating systems |
| `Diverter::original_lookup()` | Windows only: a closure from the listener's view of a connection to its `Original { client, dst, process }` |
| `Diverter::stop()` and `Drop` | Restore the network |
| `restore()` | Linux: `linux::cleanup()`. Windows: no-op |

## Linux (`linux.rs`)

`rules(config, plan, family)` generates the iptables commands below (unit-tested
verbatim).

```
-t nat -N FAKENET
-t nat -A FAKENET -m addrtype --dst-type LOCAL -j RETURN        (single host)  | -d 127.0.0.0/8 or ::1 -j RETURN (gateway)
-t nat -A FAKENET -m mark --mark 0x4b1d/0x4b1d -j RETURN         (with excluded_processes)
-t nat -A FAKENET -p tcp|udp --dport P -j RETURN                 (ignore_ports)
-t nat -A FAKENET -p icmp --icmp-type echo-request -j REDIRECT   (answer_ping; kernel replies)
-t nat -A FAKENET -p tcp --dport P -j REDIRECT --to-ports P      (fixed TCP listeners)
-t nat -A FAKENET -p tcp --dport A:B -j REDIRECT                 (FTP passive range)
-t nat -A FAKENET -p udp --dport P -j REDIRECT --to-ports P      (fixed UDP listeners)
-t nat -A FAKENET -p tcp -j REDIRECT --to-ports <auto tcp>
-t nat -A FAKENET -p udp -j REDIRECT --to-ports <auto udp>
-t nat -I OUTPUT|PREROUTING -j FAKENET
-t mangle -N FAKENET; -A FAKENET -p tcp|udp -m addrtype ! --dst-type LOCAL -m conntrack --ctstate NEW -j NFQUEUE --queue-num N --queue-bypass; -I OUTPUT -j FAKENET
```

| Item | Role |
|---|---|
| `cleanup_commands()`, `cleanup_family`, `cleanup()` | Delete the jumps (up to 8 times each) and flush and delete the chains, for v4 and v6 |
| `Active::start` | Cleans up first. Applies v4 (an error is fatal), then v6 (an error is fatal unless `ipv6 = false`). Starts the NFQUEUE thread when there are exclusions |
| `Active::stop` | Remove the rules and join the queue thread |
| `start_queue(num, excluded)` | Non-blocking NFQUEUE. For each first packet: `packet::parse`, then `find_process`, then a mark if `is_excluded(comm name)`. The verdict is always Accept |
| `is_excluded(name, list)` | Case-insensitive match on the name |
| `run(family, args)` | `iptables -w …` |

The kernel rewrites the destinations. Listeners read the original ones back with
`SO_ORIGINAL_DST` and `IP_ORIGDSTADDR`. Anything that matches no rule leaves normally.
That includes other IP protocols, non-echo ICMP, `ignore_ports`, and all IPv6 when
ip6tables NAT is missing.

## Windows (`windows.rs`, `reflect.rs`)

`reflect::Reflector` holds the pure state:

| Item | Role |
|---|---|
| `Reflector::new(plan, mode)` | Build from the plan and mode |
| `Reflector::handle(flow, now, process, excluded) -> Verdict::{Pass, Reflect{src, dst}}` | Single host: a client packet `S:sp→D:dp` is re-injected inbound as `D:sp→S:L`. The reply `S:L→D:sp` goes out as `D:dp→S:sp`. Gateway: a forwarded `C:cp→D:dp` becomes `C:cp→G:L`, and the reply goes out as `D:dp→C:cp`. UDP from a non-listener port opens an alias flow (TFTP transfer IDs). Only a SYN starts a TCP flow |
| `Reflector::original(transport, peer, local)` | Feeds `Session::new` |
| `Reflector::expire` | Idle limit 600 s, at most 65536 entries |
| `Reflector::listener_for`, `seen_peer`, `listener_address`, `insert`, `is_gateway`, `len` | Helpers |

`windows.rs` holds the I/O:

| Item | Role |
|---|---|
| `Active::start` | Opens the WinDivert socket layer (sniff), the network layer (`outbound and !loopback and (tcp or udp[ or icmp])`) and, in gateway mode, the forward layer. Then optional FixGateway and ModifyLocalDNS. Then the threads `track_owners`, `reflect_outbound` and `reflect_forwarded` |
| `track_owners` | Bind and connect events give `(transport, local port)` → PID |
| `reflect_outbound` | Answers pings itself. Looks up the owner (waiting up to 2 ms when exclusions are configured). Excludes its own PID and any name in `excluded_processes`. Rewrites with `packet::rewrite`, then re-injects |
| `reflect_forwarded` | Gateway: reflects or passes forwarded packets, and answers pings |
| `process_info`, `image_path` | `QueryFullProcessImageNameW` |
| `powershell(script)` | Runs the scripts from `host_settings.rs` |
| `Active::stop`, `restore_host_settings`, `Drop` | Restore the DNS servers and remove the added route. The WinDivert handles close when the process exits |

## `packet.rs`

| Item | Role |
|---|---|
| `parse(packet) -> Flow` | IPv4 (rejects non-first fragments and IHL < 5) or IPv6 (no extension headers), carrying TCP or UDP. Records `syn` and `fin` |
| `rewrite(packet, src, dst)` | Same address family only. Recomputes the IPv4 header checksum and the TCP/UDP checksum (a UDP checksum of 0 becomes 0xffff) |
| `echo_reply(packet)` | ICMP or ICMPv6 echo request turned into a reply |
| `internet_checksum`, `pseudo_header_sum` | Checksum helpers |

## `wire.rs`

| Item | Role |
|---|---|
| `WireCapture::start(sink)` | Linux: AF_PACKET `SOCK_DGRAM` with a 200 ms receive timeout, IPv4/IPv6 only, loopback duplicates dropped. Windows: a WinDivert sniff handle |
| `Drop` | Stops the thread. Linux joins it. On Windows it blocks until a packet arrives, so it is not joined |

## `host_settings.rs` (Windows, pure)

| Item | Role |
|---|---|
| `QUERY_DNS`, `QUERY_DEFAULT_ROUTES`, `QUERY_PRIMARY` | PowerShell queries |
| `parse_dns` | Parses the query output |
| `set_dns_script`, `restore_dns_script`, `add_route_script`, `remove_route_script` | Generated from typed values only. Routes go into the ActiveStore |
| `DnsSetting`, `PrimaryAddress` | Parsed types |
