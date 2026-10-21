#!/bin/bash
# Starts the daemon, waits for it, then runs the nucleus in the foreground (PID 1's signals
# reach it, so `docker stop` is a clean shutdown). A generated link secret authenticates the
# two to each other inside the container.
set -eu
SECRET=/opt/fakenet/link.secret
if [ ! -f "$SECRET" ]; then
    fakenet-nucleus --generate-secret "$SECRET" >/dev/null
fi

java -Dfakenet.link.secret-file="$SECRET" -Dfakenet.audit.dir=/opt/fakenet/audit \
    -jar /opt/fakenet/daemon/fakenet-daemon.jar &
DAEMON=$!
trap 'kill "$DAEMON" 2>/dev/null || true' INT TERM

# Wait for the daemon's health endpoint (loopback) before starting the nucleus
i=0
while [ "$i" -lt 60 ]; do
    # bash's /dev/tcp, in a subshell: a refused connection must not end this script
    if ( exec 3<>/dev/tcp/127.0.0.1/8092 && printf 'GET /observe/health HTTP/1.0\r\n\r\n' >&3 && head -1 <&3 ) 2>/dev/null | grep -q ' 200'; then
        break
    fi
    i=$((i + 1)); sleep 1
done

exec fakenet-nucleus -c /opt/fakenet/config/fakenet.toml
