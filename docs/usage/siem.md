# SIEM outputs

Every event and its decision can be sent to a SIEM from the daemon. The outputs are off
until configured. Source: `daemon/routes/siem.yaml`, called from the `audit` route in
`link.yaml` through a Wire Tap, so it never delays an answer.

## Properties

| Property | Format sent | Example value |
|---|---|---|
| `fakenet.siem.ecs-uris` | Elastic Common Schema JSON | `http://es:9200/fakenet/_doc`, a webhook, `file:...` |
| `fakenet.siem.splunk-uris` and `fakenet.siem.splunk-token` | Splunk HEC: `{"sourcetype":"fakenet:ecs","event":<ECS>}` with `Authorization: Splunk <token>` | `https://splunk:8088/services/collector/event` |
| `fakenet.siem.syslog-uris` | One CEF line | `netty:udp://siem:514?textline=true&sync=false` |

Each value is a comma-separated list of Camel endpoint URIs, sent in parallel. The jar bundles the `http`, `netty`, `file` and `log` components; others (Kafka, for example) need their dependency added to `daemon/pom.xml`; a failing
endpoint doesn't stop the others. Set them in `application.properties` or with `-D`.
Prefer the properties file for the Splunk token (flaw SEC-09).

## The ECS document

| Field | From |
|---|---|
| `@timestamp` | The event's timestamp |
| `event.kind`, `event.category`, `event.type`, `event.dataset` | `event`, `["network"]`, `["connection"]`, `fakenet.link` |
| `event.action` | The route (`default` when none) |
| `event.outcome` | `scripted` when a response was sent, else `default` |
| `source.ip`, `source.port`, `destination.ip`, `destination.port` | `src`, `dst` |
| `network.protocol`, `network.transport` | The event's protocol and transport |
| `process.pid`, `process.name`, `process.executable` | When known |
| `http.request.method`, `url.path`, `url.domain` | HTTP |
| `dns.question.name`, `dns.question.type` | DNS |
| `fakenet.session_id`, `request_id`, `tls`, `close`, `response_bytes` | Link fields |

## The CEF line

```text
CEF:0|FakeNet|fakenet-hybrid|1|<protocol>|<route>|3|src=... spt=... dst=... dpt=... app=<protocol> sproc=<process> cs1Label=session cs1=<session id>
```

Extension values escape `\`, `=` and newlines. Header fields don't escape `|`, so a route
name containing `|` breaks the line.

## Other sinks

Add any stock Camel component to the `audit` route's `multicast` in
`daemon/routes/link.yaml`.
