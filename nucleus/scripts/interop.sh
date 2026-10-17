#!/usr/bin/env bash
# Interoperability tests: runs the nucleus on high localhost ports (no daemon, no
# diversion), and checks that real, independent clients (curl, dig, OpenSSH, redis-cli,
# swaks, logger, nc, Python's stdlib) work with each fake service. Missing tools are skipped.
#
# Usage: scripts/interop.sh [path to fakenet-nucleus]   (KEEP_OUTPUT=1 keeps the output)
set -uo pipefail
cd "$(dirname "$0")/.."

BINARY="${1:-target/debug/fakenet-nucleus}"
WORK="$(mktemp -d)"
PASS=0; FAIL=0; SKIP=0

cleanup() {
    [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
    if [ -n "${KEEP_OUTPUT:-}" ]; then echo "Output kept in $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

check() { # name, command... (passes if the command succeeds)
    local name="$1"; shift
    if output="$("$@" 2>&1)"; then
        PASS=$((PASS + 1)); echo "PASS  $name"
    else
        FAIL=$((FAIL + 1)); echo "FAIL  $name"; echo "$output" | head -5 | sed 's/^/      /'
    fi
}
need() { command -v "$1" >/dev/null || { SKIP=$((SKIP + 1)); echo "SKIP  $2 ($1 not installed)"; return 1; }; }
event() { grep -q "$1" "$WORK/capture/events.jsonl"; } # Did a record matching this regex happen?

# A small webroot of our own (FakeNet-NG's typed default files, in miniature)
WEBROOT="$WORK/webroot"
mkdir -p "$WEBROOT"
printf 'Microsoft NCSI' > "$WEBROOT/ncsi.txt"
printf '<html><body>FakeNet</body></html>' > "$WEBROOT/FakeNet.html"
printf 'MZ\x90\x00fake executable' > "$WEBROOT/FakeNetMini.exe"
"$BINARY" --generate-secret "$WORK/link.secret" >/dev/null

listener() { # name protocol transport port [tls]
    printf '[[listener]]\nname = "%s"\nprotocol = "%s"\ntransport = "%s"\nport = %s\ntls = %s\n\n' "$1" "$2" "$3" "$4" "${5:-false}"
}
{
cat <<CONFIG
[nucleus]
bind = "127.0.0.1"
capture_dir = "$WORK/capture"
first_data_timeout_ms = 1000
health = "127.0.0.1:48099"

[daemon]
websocket_url = ""
http_url = ""
secret_file = "$WORK/link.secret"

[defaults.http]
webroot = "$WEBROOT"

[defaults.dns]
a = "192.0.2.123"
aaaa = "2001:db8::123"
mx = "mail.evil.example"

[defaults.ftp]
root = "$WEBROOT"

[defaults.tftp]
root = "$WEBROOT"

[defaults.ntp]
time_offset = 86400

CONFIG
listener Proxy auto tcp 48926
listener ProxyUDP auto udp 48926
listener HTTP http tcp 41080
listener HTTPS http tcp 41443 true
listener HTTP3 http udp 41443
listener FTP ftp tcp 41021
listener SMTP smtp tcp 41025
listener POP3 pop3 tcp 41110
listener IMAP imap tcp 41143
listener IRC irc tcp 46667
listener SSH ssh tcp 41022
listener Redis redis tcp 46379
listener SOCKS socks tcp 41081
listener DNS dns udp 41053
listener DNSTCP dns tcp 41053
listener TFTP tftp udp 41069
listener NTP ntp udp 41123
listener Syslog syslog udp 41514
listener Telnet telnet tcp 41023
listener Daytime daytime tcp 41013
listener Finger finger tcp 41079
listener SMB smb tcp 41445
listener LDAP ldap tcp 41389
listener RDP rdp tcp 43389
listener VNC vnc tcp 45900
listener MQTT mqtt tcp 41883
listener CoAP coap udp 45683
listener DoT dns tcp 41853 true
} > "$WORK/fakenet.toml"

"$BINARY" -c "$WORK/fakenet.toml" > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 100); do curl -sf http://127.0.0.1:48099/health >/dev/null 2>&1 && break; sleep 0.2; done
curl -sf http://127.0.0.1:48099/health >/dev/null || { echo "The nucleus failed to start:"; cat "$WORK/server.log"; exit 1; }
CA="$WORK/capture/ca.pem"
TOKEN="$(tr -d '\n' < "$WORK/link.secret")"
echo "Nucleus running (pid $SERVER_PID); output in $WORK/capture"
echo

# --- Health ---
check "Health: no details without the token" sh -c "[ \"\$(curl -sf http://127.0.0.1:48099/health)\" = '{\"status\":\"ok\"}' ]"
check "Health: details with the token" sh -c "curl -sf -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:48099/health | grep -q '\"listeners\"'"

# --- HTTP & TLS ---
if need curl "curl tests"; then
    check "HTTP: curl gets the default file for any .exe" \
        sh -c "curl -sf http://127.0.0.1:41080/download/payload.exe | cmp - '$WEBROOT/FakeNetMini.exe'"
    check "HTTP: POST bodies are captured" \
        sh -c "curl -sf -d 'id=42&os=win' http://127.0.0.1:41080/gate.php >/dev/null && sleep 0.3 && grep -q 'id=42&os=win' '$WORK'/capture/files/http_body_*"
    check "HTTPS: curl verifies the minted certificate for the requested hostname" \
        curl -sf --cacert "$CA" --resolve update.evil.example:41443:127.0.0.1 https://update.evil.example:41443/ -o /dev/null
    check "HTTPS: a bare IP (no SNI) gets a certificate for that IP" \
        curl -sf --cacert "$CA" https://127.0.0.1:41443/ -o /dev/null
    check "HTTPS: an untrusted client is rejected by TLS verification (no CA)" \
        sh -c "! curl -sf --resolve x.example:41443:127.0.0.1 https://x.example:41443/ -o /dev/null"
    check "HTTP/2: negotiated with ALPN" \
        sh -c "[ \"\$(curl -sf --http2 --cacert '$CA' --resolve h2.example:41443:127.0.0.1 https://h2.example:41443/ -o /dev/null -w '%{http_version}')\" = 2 ]"
    if curl -V | grep -q HTTP3; then
        check "HTTP/3: curl over QUIC" \
            sh -c "[ \"\$(curl -sf --http3-only --cacert '$CA' --resolve h3.example:41443:127.0.0.1 https://h3.example:41443/ -o /dev/null -w '%{http_version}')\" = 3 ]"
    else
        SKIP=$((SKIP + 1)); echo "SKIP  HTTP/3 (this curl has no HTTP/3)"
    fi
    check "HTTP CONNECT tunnel, with TLS inside, through the HTTP listener" \
        curl -sf -x http://127.0.0.1:41080 --proxytunnel --cacert "$CA" https://tunneled.example/ -o /dev/null
    check "SOCKS5 tunnel (remote DNS) into protocol detection" \
        curl -sf -x socks5h://127.0.0.1:41081 http://socks.example/ncsi.txt -o /dev/null
    check "SOCKS4a tunnel" \
        curl -sf -x socks4a://127.0.0.1:41081 http://socks4.example/ -o /dev/null
    check "Proxy port: plain HTTP is detected" \
        curl -sf http://127.0.0.1:48926/ -o /dev/null
    check "Proxy port: HTTPS is unwrapped & detected" \
        curl -sf --cacert "$CA" --resolve proxied.example:48926:127.0.0.1 https://proxied.example:48926/ -o /dev/null

    # --- File transfer ---
    check "FTP: passive download" \
        sh -c "curl -sf ftp://127.0.0.1:41021/ncsi.txt | cmp - '$WEBROOT/ncsi.txt'"
    check "FTP: directory listing" \
        sh -c "curl -sf --list-only ftp://127.0.0.1:41021/ | grep -q FakeNet.html"
    echo "exfiltrated" > "$WORK/upload.txt"
    check "FTP: uploads are captured" \
        sh -c "curl -sf -T '$WORK/upload.txt' ftp://user:pw@127.0.0.1:41021/upload.txt && sleep 0.3 && grep -q exfiltrated '$WORK'/capture/files/ftp_*"
    check "TFTP: download" \
        sh -c "curl -sf tftp://127.0.0.1:41069/ncsi.txt | cmp - '$WEBROOT/ncsi.txt'"
    check "TFTP: uploads are captured" \
        sh -c "curl -sf -T '$WORK/upload.txt' tftp://127.0.0.1:41069/stolen.txt && sleep 0.3 && grep -q exfiltrated '$WORK'/capture/files/tftp_*"

    # --- Mail ---
    printf 'Subject: Interop\r\n\r\nHello from curl\r\n' > "$WORK/mail.txt"
    check "SMTP: curl sends a message" \
        sh -c "curl -sf smtp://127.0.0.1:41025 --mail-from bot@evil.example --mail-rcpt victim@corp.example -T '$WORK/mail.txt' && sleep 0.3 && grep -q 'Hello from curl' '$WORK'/capture/files/smtp_*"
    check "POP3: curl retrieves the message" \
        sh -c "curl -sf pop3://user:pass@127.0.0.1:41110/1 | grep -q 'Subject: FakeNet'"
    check "IMAP: curl fetches the message" \
        sh -c "curl -sf 'imap://user:pass@127.0.0.1:41143/INBOX;UID=1' | grep -q 'Subject: FakeNet'"
fi

if need swaks "SMTP STARTTLS + AUTH"; then
    check "SMTP: swaks with STARTTLS & AUTH LOGIN" \
        sh -c "swaks --server 127.0.0.1:41025 --tls --auth LOGIN --auth-user mailbot --auth-password hunter2 \
               --from a@b.example --to c@d.example --body 'over tls' >/dev/null && sleep 0.3 && \
               grep -q '\"kind\":\"credentials\".*mailbot' '$WORK/capture/events.jsonl'"
fi

if need python3 "Python stdlib clients"; then
    check "Python smtplib/poplib/imaplib: STARTTLS/STLS with certificate verification" python3 - "$CA" <<'PY'
import imaplib, poplib, smtplib, ssl, sys
context = ssl.create_default_context(cafile=sys.argv[1])
context.check_hostname = False  # Connecting by IP; the chain is still verified
with smtplib.SMTP("127.0.0.1", 41025, timeout=5) as smtp:
    smtp.starttls(context=context)
    smtp.login("py", "secret")
    smtp.sendmail("a@b.example", ["c@d.example"], "Subject: py\r\n\r\nbody")
pop = poplib.POP3("127.0.0.1", 41110, timeout=5)
pop.stls(context=context)
pop.user("u"); pop.pass_("p")
assert b"Subject: FakeNet" in b"\r\n".join(pop.retr(1)[1])
pop.quit()
imap = imaplib.IMAP4("127.0.0.1", 41143, timeout=5)
imap.starttls(ssl_context=context)
imap.login("u", "p")
imap.select("INBOX")
typ, data = imap.fetch("1", "(RFC822)")
assert typ == "OK" and b"Subject: FakeNet" in data[0][1], data
imap.logout()
PY
    check "Python ftplib: active mode (PORT) back to the client" python3 - <<'PY'
import ftplib, io
ftp = ftplib.FTP()
ftp.connect("127.0.0.1", 41021, timeout=5)
ftp.login("anonymous", "a@b")
ftp.set_pasv(False)
out = io.BytesIO()
ftp.retrbinary("RETR ncsi.txt", out.write)
assert out.getvalue().startswith(b"Microsoft NCSI"), out.getvalue()
ftp.quit()
PY
    check "NTP: client gets a server reply, shifted by time_offset" python3 - <<'PY'
import socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(b"\x23" + 47 * b"\0", ("127.0.0.1", 41123))
reply = s.recv(48)
assert reply[0] & 7 == 4, reply[0]
served = struct.unpack("!I", reply[40:44])[0] - 2208988800
assert abs(served - (time.time() + 86400)) < 5, served
PY
    check "IRC: registration & PING over a raw socket" python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 46667), timeout=5)
s.sendall(b"NICK bot\r\nUSER bot 0 * :bot\r\nPING :tok\r\nQUIT\r\n")
data = b""
while True:
    chunk = s.recv(4096)
    if not chunk: break
    data += chunk
assert b" 001 bot " in data and b"PONG" in data and b"ERROR :Closing Link" in data, data
PY
fi

# --- DNS ---
if need dig "DNS tests"; then
    check "DNS: A over UDP" sh -c "[ \"\$(dig +short +tries=1 +time=3 @127.0.0.1 -p 41053 evil.example A)\" = 192.0.2.123 ]"
    check "DNS: AAAA" sh -c "[ \"\$(dig +short +tries=1 +time=3 @127.0.0.1 -p 41053 evil.example AAAA)\" = 2001:db8::123 ]"
    check "DNS: MX" sh -c "dig +short +tries=1 +time=3 @127.0.0.1 -p 41053 evil.example MX | grep -q 'mail.evil.example'"
    check "DNS: TXT" sh -c "dig +short +tries=1 +time=3 @127.0.0.1 -p 41053 evil.example TXT | grep -q FAKENET"
    check "DNS: over TCP" sh -c "[ \"\$(dig +short +tcp +tries=1 +time=3 @127.0.0.1 -p 41053 evil.example A)\" = 192.0.2.123 ]"
    check "DNS: on the proxy's UDP port" sh -c "dig +short +tries=1 +time=3 @127.0.0.1 -p 48926 proxied.example A | grep -q '^[0-9]'"
fi

# --- Others ---
if need ssh "SSH fingerprinting"; then
    ssh -p 41022 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 interop@127.0.0.1 true >/dev/null 2>&1
    sleep 0.3
    check "SSH: OpenSSH's version & HASSH fingerprint are logged" \
        sh -c "grep '\"kind\":\"ssh_client\"' '$WORK/capture/events.jsonl' | grep -q '\"hassh\":\"[0-9a-f]\{32\}\".*\"version\":\"SSH-2.0-OpenSSH'"
fi
if need redis-cli "Redis"; then
    check "Redis: redis-cli PING" sh -c "[ \"\$(redis-cli -p 46379 PING)\" = PONG ]"
    check "Redis: attack commands are flagged" sh -c "redis-cli -p 46379 CONFIG SET dir /var/spool/cron >/dev/null && sleep 0.3 && grep -q '\"command\":\"CONFIG\".*\"kind\":\"suspicious_command\"' '$WORK/capture/events.jsonl'"
fi
if need logger "Syslog"; then
    check "Syslog: logger's RFC 5424 message is collected" \
        sh -c "logger -n 127.0.0.1 -P 41514 -d --rfc5424 'interop syslog test' && sleep 0.3 && grep -q 'interop syslog test' '$WORK/capture/events.jsonl'"
fi
if need nc "Telnet, small services & proxy detection"; then
    check "Telnet: login & busybox probe" \
        sh -c "printf 'root\r\nvizxv\r\n/bin/busybox ECCHI\r\nexit\r\n' | nc -q 3 127.0.0.1 41023 | grep -q 'ECCHI: applet not found'"
    check "Daytime: the date" sh -c "nc -q 3 127.0.0.1 41013 < /dev/null | grep -q -- '-UTC'"
    check "Finger: a user" sh -c "printf 'root\r\n' | nc -q 3 127.0.0.1 41079 | grep -q 'Login: root'"
    check "Proxy port: an SMTP client is detected from EHLO" \
        sh -c "printf 'EHLO x\r\nQUIT\r\n' | nc -q 3 127.0.0.1 48926 | grep -q '^250'"
fi

# --- Windows & IoT protocols ---
records() { grep "\"kind\":\"$1\"" "$WORK/capture/events.jsonl"; }
# A captured NetNTLMv2 hash for a user must crack to the expected secret (when john is here)
cracks() { # user secret
    records credentials | grep "\"username\":\"$1\"" | grep -o '"hash":"[^"]*"' | cut -d'"' -f4 > "$WORK/$1.hash"
    [ -s "$WORK/$1.hash" ] || return 1
    command -v john >/dev/null || return 0
    printf '%s\nnot-it\n' "$2" > "$WORK/$1.words"
    john --format=netntlmv2 --wordlist="$WORK/$1.words" --pot="$WORK/$1.pot" "$WORK/$1.hash" >/dev/null 2>&1
    john --show --format=netntlmv2 --pot="$WORK/$1.pot" "$WORK/$1.hash" | grep -q ":$2:"
}
SMB_SECRET='S3cret-smb'
if need smbclient "SMB"; then
    smbclient -L 127.0.0.1 -p 41445 -U "CORP\\smbuser%$SMB_SECRET" >/dev/null 2>&1
    sleep 0.3
    check "SMB: smbclient's NTLMv2 logon is captured (and cracks)" cracks smbuser "$SMB_SECRET"
    check "SMB: the dialects offered are logged" sh -c "grep '\"kind\":\"smb_negotiate\"' '$WORK/capture/events.jsonl' | grep -q '3.1.1'"
fi
LDAP_SECRET='Bind-pw-1'
if need ldapsearch "LDAP"; then
    check "LDAP: ldapsearch reads the root DSE" sh -c "ldapsearch -x -H ldap://127.0.0.1:41389 -s base -b '' defaultNamingContext | grep -q 'DC=fakenet,DC=local'"
    ldapsearch -x -H ldap://127.0.0.1:41389 -D 'CN=svc,DC=corp' -w "$LDAP_SECRET" -b 'DC=corp' '(&(objectClass=user)(adminCount=1))' >/dev/null 2>&1
    sleep 0.3
    check "LDAP: a simple bind's password is captured" sh -c "grep -q '\"password\":\"$LDAP_SECRET\"' '$WORK/capture/events.jsonl'"
    check "LDAP: the search filter is rendered" sh -c "grep -q '(&(objectClass=user)(adminCount=1))' '$WORK/capture/events.jsonl'"
fi
FREERDP="$(command -v xfreerdp3 || command -v xfreerdp || true)"
RDP_SECRET='Rdp-pw-22'
if [ -n "$FREERDP" ]; then
    timeout 20 "$FREERDP" /v:127.0.0.1:43389 /u:rdpuser /d:CORP /p:"$RDP_SECRET" /cert:ignore +auth-only >/dev/null 2>&1
    sleep 0.3
    check "RDP: FreeRDP's cookie and NLA NTLM hash are captured (and cracks)" cracks rdpuser "$RDP_SECRET"
else
    SKIP=$((SKIP + 1)); echo "SKIP  RDP (xfreerdp not installed)"
fi
if need python3 "MQTT, CoAP & WebSocket"; then
    check "MQTT: a CONNECT's credentials are captured" sh -c "python3 scripts/interop-iot.py mqtt 41883 | grep -q OK && sleep 0.3 && grep -q '\"mechanism\":\"MQTT\"' '$WORK/capture/events.jsonl'"
    check "CoAP: a GET of /.well-known/core is answered" sh -c "python3 scripts/interop-iot.py coap 45683 | grep -q OK && grep -q '/.well-known/core' '$WORK/capture/events.jsonl'"
    check "WebSocket: an HTTP upgrade carries a message to the capture" sh -c "python3 scripts/interop-iot.py ws 41080 | grep -q OK && sleep 0.3 && grep -q '\"kind\":\"websocket_message\"' '$WORK/capture/events.jsonl'"
fi

# --- Report & import ---
sleep 0.5
check "Report: the HTML report covers the interop traffic" \
    sh -c "'$BINARY' --report '$WORK/capture/events.jsonl' -o '$WORK/report.html' >/dev/null && \
           grep -q 'evil.example (A)' '$WORK/report.html' && grep -q 'username=mailbot' '$WORK/report.html' && \
           grep -q 'hassh=' '$WORK/report.html' && ! grep -qi '<script' '$WORK/report.html'"
check "Import: FakeNet-NG's default.ini converts to a valid config" \
    sh -c "'$BINARY' --import-fakenet-ini crates/cli/tests/fixtures/fakenet-ng-default.ini -o '$WORK/imported.toml' && '$BINARY' --check -c '$WORK/imported.toml'"

echo
echo "$PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
