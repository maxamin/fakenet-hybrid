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
    private final LinkAuth auth;

    public EventIn(LinkAuth auth) {
        this.auth = auth;
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
        if (!auth.verify(LinkAuth.eventText((String) event.get("request_id"), (String) event.get("session_id"), payloadBase64), event.get("auth"))) {
            reject(message, "unsigned or forged event");
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
        if (event.get("process") instanceof Map<?, ?> process) {
            message.setHeader(PROCESS, process.get("name"));
            message.setHeader(PID, process.get("pid"));
        }
        message.setHeader(PAYLOAD, payload);
        message.setHeader(TEXT, new String(payload, StandardCharsets.UTF_8));
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
