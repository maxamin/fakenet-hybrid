#!/bin/sh
# Installs a FakeNet hybrid package (unpacked; run from its top directory) as two systemd
# services. Inside the analysis VM only. It never enables diversion: review
# /etc/fakenet/fakenet.toml and set [diverter] enabled = true yourself.
set -eu
[ "$(id -u)" = 0 ] || { echo "Run as root" >&2; exit 1; }
command -v java >/dev/null || { echo "Java 21 is required (e.g. apt install openjdk-21-jre-headless)" >&2; exit 1; }

install -d /opt/fakenet-hybrid/bin /opt/fakenet-hybrid/daemon /etc/fakenet /var/lib/fakenet
install -m 0755 bin/fakenet-nucleus /opt/fakenet-hybrid/bin/
cp -r daemon/fakenet-daemon.jar daemon/lib daemon/routes /opt/fakenet-hybrid/daemon/
cp -r config/default-files /opt/fakenet-hybrid/
id fakenet >/dev/null 2>&1 || useradd --system --home /var/lib/fakenet --shell /usr/sbin/nologin fakenet
install -d -o fakenet -g fakenet /var/lib/fakenet/audit
chown -R fakenet:fakenet /opt/fakenet-hybrid/daemon/routes

if [ ! -e /etc/fakenet/fakenet.toml ]; then
    sed -e 's|^capture_dir = .*|capture_dir = "/var/lib/fakenet/capture"|' \
        -e 's|"default-files"|"/opt/fakenet-hybrid/default-files"|' \
        -e 's|^# *secret_file = .*|secret_file = "/etc/fakenet/link.secret"|' config/fakenet.toml > /etc/fakenet/fakenet.toml
fi
if [ ! -e /etc/fakenet/link.secret ]; then
    /opt/fakenet-hybrid/bin/fakenet-nucleus --generate-secret /etc/fakenet/link.secret
    chown root:fakenet /etc/fakenet/link.secret
    chmod 0640 /etc/fakenet/link.secret
fi
install -m 0644 deploy/linux/fakenet-nucleus.service deploy/linux/fakenet-daemon.service /etc/systemd/system/
systemctl daemon-reload
echo "Installed. Review /etc/fakenet/fakenet.toml, then: systemctl enable --now fakenet-daemon fakenet-nucleus"
