package lab.fakenet.daemon;

import static lab.fakenet.daemon.LinkSchema.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;

/**
 * Parses and validates a nucleus message, setting FakenetKind:
 * <ul>
 * <li>"hello": a WebSocket handshake; the body is the signed reply to send back</li>
 * <li>"rejected": malformed, or not signed with the link secret; drop it</li>
 * <li>"event": an Event, exposed as Fakenet* headers. The body becomes empty: a route
 * answers by setting the body, and a route that leaves it empty gets the nucleus's
 * built-in default.</li>
 * </ul>
 */
public class EventIn implements Processor {
    /** Payloads up to this size are also given to rules as text (FakenetText) */
    static final int MAX_TEXT = 1024 * 1024;

    /** How far an authenticated event's timestamp may be from now */
    static final java.time.Duration WINDOW = java.time.Duration.ofMinutes(5);
    /** request_ids remembered to refuse replays (at least as long as WINDOW, at most this many) */
    static final int SEEN = 100_000;

    private final LinkAuth auth;
    /** request_id -> when it was seen, oldest first */
    private final Map<String, Long> seen = new java.util.LinkedHashMap<>(16, 0.75f, false) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
            return size() > SEEN;
        }
    };

    public EventIn(LinkAuth auth) {
        this.auth = auth;
    }

    /**
     * Replay protection on an authenticated link: a signed event is accepted once, and only
     * near its timestamp. Null when it is fresh, else why not.
     */
    String replayed(Map<String, Object> event, String requestId) {
        if (!auth.enabled()) {
            return null;
        }
        long now = System.currentTimeMillis();
        try {
            long at = java.time.OffsetDateTime.parse(String.valueOf(event.get("timestamp"))).toInstant().toEpochMilli();
            if (Math.abs(now - at) > WINDOW.toMillis()) {
                return "stale timestamp";
            }
        } catch (java.time.format.DateTimeParseException e) {
            return "bad timestamp";
        }
        synchronized (seen) {
            seen.values().removeIf(t -> now - t > 2 * WINDOW.toMillis());
            if (seen.putIfAbsent(requestId, now) != null) {
                return "replayed request_id";
            }
        }
        return null;
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        Message message = exchange.getMessage();
        String json = message.getMandatoryBody(String.class);
        Map<String, Object> event;
        try {
            event = JSON.readValue(json, new TypeReference<>() {});
        } catch (Exception e) {
            reject(message, "not JSON");
            return;
        }
        if (!Integer.valueOf(VERSION).equals(event.get("version"))) {
            reject(message, "unsupported version");
            return;
        }
        if ("hello".equals(event.get("type")) && event.get("nonce") instanceof String nonce) {
            Map<String, Object> reply = new java.util.LinkedHashMap<>();
            reply.put("version", VERSION);
            reply.put("type", "hello");
            reply.put("nonce", nonce);
            reply.put("auth", auth.sign(LinkAuth.helloText(nonce)));
            message.setHeader(KIND, "hello");
            message.setBody(JSON.writeValueAsString(reply));
            return;
        }
        if (!"event".equals(event.get("type")) || !(event.get("request_id") instanceof String)
            || !(event.get("session_id") instanceof String) || !(event.get("payload") instanceof String)) {
            reject(message, "not an event");
            return;
        }
        String payloadBase64 = (String) event.get("payload");
        if (!auth.unseal(json)) {
            reject(message, "unsigned or forged event");
            return;
        }
        String replay = replayed(event, (String) event.get("request_id"));
        if (replay != null) {
            reject(message, replay);
            return;
        }
        message.setHeader(KIND, "event");
        String requestId = requiredString(event, "request_id");
        byte[] payload = Base64.getDecoder().decode(payloadBase64);
        Map<?, ?> meta = event.get("meta") instanceof Map<?, ?> m ? m : Map.of();

        exchange.setProperty(EVENT_JSON, json);
        message.setHeader(REQUEST_ID, requestId);
        message.setHeader(SESSION_ID, requiredString(event, "session_id"));
        message.setHeader(SEQ, event.get("seq"));
        message.setHeader(PROTOCOL, requiredString(event, "protocol"));
        message.setHeader(TRANSPORT, event.get("transport"));
        message.setHeader(TLS, Boolean.TRUE.equals(event.get("tls")));
        message.setHeader(SRC, event.get("src"));
        message.setHeader(DST, event.get("dst"));
        message.setHeader(DPORT, event.get("dport"));
        String source = String.valueOf(event.get("src"));
        message.setHeader(ACTOR, "ip:" + (source.contains(":") ? source.substring(0, source.lastIndexOf(':')) : source));
        if (event.get("process") instanceof Map<?, ?> process) {
            message.setHeader(PROCESS, process.get("name"));
            message.setHeader(PID, process.get("pid"));
            message.setHeader(ACTOR, "pid:" + process.get("pid"));
        }
        message.setHeader(PAYLOAD, payload);
        // As text for rules; skipped for large payloads (one more copy each, rarely matched as text)
        message.setHeader(TEXT, payload.length <= MAX_TEXT ? new String(payload, StandardCharsets.UTF_8) : "");
        message.setHeader(META, meta);
        message.setHeader(EXPECTS_REPLY, !Boolean.FALSE.equals(event.get("expects_reply")));
        message.setHeader(METHOD, meta.get("method"));
        message.setHeader(PATH, meta.get("path"));
        message.setHeader(HOST, meta.get("host"));
        message.setHeader(QNAME, meta.get("qname"));
        message.setHeader(QTYPE, meta.get("qtype"));
        message.setBody(null);
    }

    private static void reject(Message message, String reason) {
        message.setHeader(KIND, "rejected");
        message.setHeader(REJECTED_REASON, reason);
        message.setBody(null);
    }

    private static String requiredString(Map<String, Object> event, String field) {
        if (event.get(field) instanceof String value) {
            return value;
        }
        throw new IllegalArgumentException("Event field " + field + " is missing");
    }
}
