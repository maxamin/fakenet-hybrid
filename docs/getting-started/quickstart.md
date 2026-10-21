# Quick start

This walks through one interactive analysis session on a Linux analysis VM. Every command
runs inside the VM.

## 1. Build

```sh
cd nucleus && cargo build --release
cd ../daemon && mvn package
```

## 2. Create the link secret

The secret authenticates the nucleus and the daemon to each other, so a local process
can't pose as either side.

```sh
cd nucleus
./target/release/fakenet-nucleus --generate-secret config/link.secret   # 0600, 64 hex chars
```

`--generate-secret` refuses to overwrite an existing file.

## 3. Configure

Copy `config/fakenet.toml` to, say, `config/my.toml` and set:

```toml
[daemon]
secret_file = "link.secret"          # relative to this config file

[diverter]
enabled = true                       # this VM only

[defaults.dns]
a = "10.0.0.5"                       # an address the sample should reach, e.g. the VM's own
```

Remove or fix the `fingerprints = [...]` line if `config/fingerprints/` is not next to your
config. Then validate:

```sh
./target/release/fakenet-nucleus --check -c config/my.toml
```

## 4. Start the daemon

From `daemon/`, so it finds `routes/`:

```sh
cd ../daemon
java -Dfakenet.link.secret-file=../nucleus/config/link.secret -jar target/fakenet-daemon.jar
```

Wait for `Rules warmed up; link channels started`. Until then the nucleus answers with its
defaults.

## 5. Start the nucleus

```sh
cd ../nucleus
sudo ./target/release/fakenet-nucleus -c config/my.toml
```

On the first start it creates the interception CA in `config/ca/` (`ca_cert` and `ca_key`)
and copies the certificate to `config/capture/ca.pem`. Install it as a trusted root in the
VM once (for example `sudo cp config/capture/ca.pem /usr/local/share/ca-certificates/fakenet.crt &&
sudo update-ca-certificates`) so HTTPS, SMTPS and STARTTLS look valid. Later starts reuse it.

```{note}
Without `ca_cert` and `ca_key` the nucleus makes a new CA at every start, which must be
installed again each time.
```

## 6. Check and watch

```sh
curl -H "Authorization: Bearer $(cat config/link.secret)" http://127.0.0.1:8099/health
curl http://127.0.0.1:8092/observe/health
curl -s http://example.com/ | head -3          # answered by the nucleus
dig +short anything.example                    # 10.0.0.5
```

Open `http://127.0.0.1:8099/dashboard?token=<contents of link.secret>` for the live view.

## 7. Run the sample, then stop

Run the sample, watch the dashboard, then press **Ctrl+C** in the nucleus terminal. Shutdown
removes the iptables rules, finishes YARA scans and writes `report.html` and
`indicators.*` into `config/capture/`.

```{warning}
Stopping the nucleus removes the diversion. On Linux outbound traffic stays blocked until
`--restore-network`; on Windows anything the sample left running then has the real network
(flaw LEAK-01). Revert the VM, or kill the sample first.
```

If the nucleus was killed (`kill -9`, power loss), clean up with
`sudo fakenet-nucleus --restore-network`.

## One-shot alternative

```sh
sudo ./target/release/fakenet-nucleus -c config/my.toml --run ./sample --timeout 300
```

This starts everything, runs the sample, stops when it exits (plus 5 s) or at the timeout,
and writes everything into `capture/<time>-<name>-<sha256[:12]>/` with a `run.json`. See
{doc}`../usage/cli`.
