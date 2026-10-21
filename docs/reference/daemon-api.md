# Daemon reference

Package `lab.fakenet.daemon` (`daemon/src/main/java/`). See {doc}`../architecture/daemon`
for how the pieces fit together.

## Beans available to routes

| Bean | Class | Use |
|---|---|---|
| `eventIn` | `EventIn` | `- process: {ref: eventIn}` |
| `actionOut` | `ActionOut` | `- process: {ref: actionOut}` |
| `warmUp` | `WarmUp` | Used by `decide-warm-up` |
| `state` | `SessionState` | From Groovy: `camelContext.registry.lookupByName('state')`. From Simple: `${bean:state?method=get(${header.FakenetActor}, 'stage')}` |

## `SessionState`

| Method | Returns |
|---|---|
| `get(actor, key)` | The value or `null` |
| `get(actor, key, fallback)` | The value or `fallback` |
| `put(actor, key, value)` | — |
| `increment(actor, key)` | The new count (1 the first time) |
| `all(actor)` | A copy of the actor's map |
| `forget(actor)` | — |

Every call refreshes the actor's idle timer (1 hour).

## `LinkAuth`

| Method | Description |
|---|---|
| `static load(path)` | Blank path: unauthenticated. Otherwise reads, trims, requires 32+ characters |
| `enabled()` | Whether a secret is loaded |
| `sign(text)` | Hex HMAC-SHA256, or `null` without a secret |
| `verify(text, signature)` | `true` without a secret; otherwise a constant-time comparison |
| `static helloText`, `eventText`, `actionText` | The signed texts (same as the nucleus) |

## `LinkSchema` constants

Header names (`FakenetKind`, `FakenetRejectedReason`, `FakenetRequestId`,
`FakenetSessionId`, `FakenetSeq`, `FakenetProtocol`, `FakenetTransport`, `FakenetTls`,
`FakenetSrc`, `FakenetDst`, `FakenetDport`, `FakenetProcess`, `FakenetPid`,
`FakenetActor`, `FakenetPayload`, `FakenetText`, `FakenetMeta`, `FakenetExpectsReply`,
`FakenetMethod`, `FakenetPath`, `FakenetHost`, `FakenetQname`, `FakenetQtype`,
`FakenetClose`, `FakenetDelayMs`, `FakenetRoute`), the exchange property
`FakenetEventJson`, `VERSION`, `MAX_DELAY_MS` and the shared `JSON` `ObjectMapper`.

## Tests (`daemon/src/test/java/lab/fakenet/daemon/`)

| Test | Covers |
|---|---|
| `LinkAuthTest` | The shared HMAC vectors |
| `LinkProcessorsTest` | `EventIn` and `ActionOut` |
| `DecisionRulesTest` | The rules in `routes/decisions.yaml` |
| `LibraryRulesTest` | Every file in `rules-library/`, loaded and exercised |
| `SessionStateTest` | The `state` bean |
| `SiemTest` | ECS, Splunk and CEF documents through mock endpoints |
