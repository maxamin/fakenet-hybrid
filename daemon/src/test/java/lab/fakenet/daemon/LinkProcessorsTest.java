package lab.fakenet.daemon;

import static lab.fakenet.daemon.LinkSchema.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.support.DefaultExchange;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.core.type.TypeReference;

class LinkProcessorsTest {
    private final CamelContext context = new DefaultCamelContext();

    private Exchange exchange(String body) {
        Exchange exchange = new DefaultExchange(context);
        exchange.getMessage().setBody(body);
        return exchange;
    }

    private static String event(LinkAuth auth, String payloadBase64, boolean signed) throws Exception {
        Map<String, Object> event = new java.util.LinkedHashMap<>(Map.of(
            "version", 1, "type", "event", "request_id", "req-1", "session_id", "tcp-0000000000000001", "seq", 1,
            "protocol", "http", "transport", "tcp", "src", "10.0.0.5:1234", "dst", "1.2.3.4:80"));
        event.putAll(Map.of("dport", 80, "timestamp", "t", "payload", payloadBase64, "expects_reply", true,
            "meta", Map.of("path", "/gate.php", "host", "c2.example")));
        if (signed) {
            event.put("auth", auth.sign(LinkAuth.eventText("req-1", "tcp-0000000000000001", payloadBase64)));
        }
        return JSON.writeValueAsString(event);
    }

    @Test
    void answersTheHandshakeAndRejectsForgeries(@TempDir Path dir) throws Exception {
        LinkAuth auth = LinkAuthTest.auth(dir);
        EventIn in = new EventIn(auth);

        Exchange hello = exchange("{\"version\":1,\"type\":\"hello\",\"nonce\":\"abc\"}");
        in.process(hello);
        assertEquals("hello", hello.getMessage().getHeader(KIND));
        Map<String, Object> reply = JSON.readValue(hello.getMessage().getBody(String.class), new TypeReference<>() {});
        assertEquals(auth.sign(LinkAuth.helloText("abc")), reply.get("auth"));

        String payload = Base64.getEncoder().encodeToString("GET /gate.php HTTP/1.1\r\n\r\n".getBytes());
        Exchange forged = exchange(event(auth, payload, false));
        in.process(forged);
        assertEquals("rejected", forged.getMessage().getHeader(KIND));
        assertEquals("unsigned or forged event", forged.getMessage().getHeader(REJECTED_REASON));

        Exchange garbage = exchange("not json");
        in.process(garbage);
        assertEquals("rejected", garbage.getMessage().getHeader(KIND));
    }

    @Test
    void exposesEventsAsHeadersAndSignsActions(@TempDir Path dir) throws Exception {
        LinkAuth auth = LinkAuthTest.auth(dir);
        String payload = Base64.getEncoder().encodeToString("PING".getBytes());
        Exchange exchange = exchange(event(auth, payload, true));
        new EventIn(auth).process(exchange);
        var message = exchange.getMessage();
        assertEquals("event", message.getHeader(KIND));
        assertEquals("http", message.getHeader(PROTOCOL));
        assertEquals("/gate.php", message.getHeader(PATH));
        assertEquals("PING", message.getHeader(TEXT));
        assertNull(message.getBody()); // Empty body: the nucleus's default, unless a rule answers

        // A Groovy GString-like CharSequence body (Camel has no converter for it)
        message.setBody(new StringBuilder("PONG\n"));
        message.setHeader(CLOSE, true);
        new ActionOut(auth).process(exchange);
        Map<String, Object> action = JSON.readValue(message.getBody(String.class), new TypeReference<>() {});
        assertEquals("UE9ORwo=", action.get("response"));
        assertEquals(true, action.get("close"));
        assertEquals(auth.sign(LinkAuth.actionText("req-1", "tcp-0000000000000001", "UE9ORwo=", true, null)), action.get("auth"));
    }
}
