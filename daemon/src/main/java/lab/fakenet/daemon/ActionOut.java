package lab.fakenet.daemon;

import static lab.fakenet.daemon.LinkSchema.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;

/**
 * Turns the route's result into an Action: the body (any type Camel can convert to bytes)
 * is the response, an empty body means "use the nucleus's default", and the FakenetClose,
 * FakenetDelayMs & FakenetRoute headers become the other fields.
 */
public class ActionOut implements Processor {
    private final LinkAuth auth;

    public ActionOut(LinkAuth auth) {
        this.auth = auth;
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        Message message = exchange.getMessage();
        byte[] response = responseBytes(message.getBody(), message);

        Map<String, Object> action = new LinkedHashMap<>();
        action.put("version", VERSION);
        action.put("type", "action");
        action.put("request_id", message.getHeader(REQUEST_ID, String.class));
        action.put("session_id", message.getHeader(SESSION_ID, String.class));
        String responseBase64 = response == null ? null : Base64.getEncoder().encodeToString(response);
        boolean close = Boolean.TRUE.equals(message.getHeader(CLOSE, Boolean.class));
        Long delay = message.getHeader(DELAY_MS, Long.class);
        if (delay != null) {
            delay = Math.max(0, Math.min(delay, MAX_DELAY_MS));
        }
        action.put("response", responseBase64);
        action.put("close", close);
        if (delay != null) {
            action.put("delay_ms", delay);
        }
        action.put("route", message.getHeader(ROUTE, "default", String.class));
        String signature = auth.sign(LinkAuth.actionText((String) action.get("request_id"), (String) action.get("session_id"), responseBase64, close, delay));
        if (signature != null) {
            action.put("auth", signature);
        }
        message.setBody(JSON.writeValueAsString(action));
    }

    /** Never fails: text (including Groovy GStrings, which Camel can't convert) is UTF-8 */
    static byte[] responseBytes(Object body, Message message) {
        if (body == null) {
            return null;
        }
        if (body instanceof CharSequence text) {
            return text.toString().getBytes(StandardCharsets.UTF_8);
        }
        byte[] bytes = message.getBody(byte[].class);
        return bytes != null ? bytes : String.valueOf(body).getBytes(StandardCharsets.UTF_8);
    }
}
