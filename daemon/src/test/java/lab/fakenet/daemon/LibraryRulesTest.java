package lab.fakenet.daemon;

import static lab.fakenet.daemon.LinkSchema.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.support.DefaultExchange;
import org.apache.camel.support.PluginHelper;
import org.apache.camel.support.ResourceHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The rules library (rules-library/*.yaml), loaded as shipped */
class LibraryRulesTest {
    private CamelContext context;
    private ProducerTemplate template;

    @BeforeEach
    void start() throws Exception {
        context = new DefaultCamelContext();
        context.getRegistry().bind("state", new SessionState());
        context.getPropertiesComponent().addInitialProperty("fakenet.library.tasks", "whoami,sleep 60");
        context.getPropertiesComponent().addInitialProperty("fakenet.library.kill-switch-domains", "kill.example, other-kill.example");
        for (String file : List.of("staged-http-c2.yaml", "dns-txt-tasking.yaml", "irc-botnet.yaml", "kill-switch.yaml", "recorded-example.yaml")) {
            PluginHelper.getRoutesLoader(context).loadRoutes(ResourceHelper.resolveResource(context, "file:" + Path.of("rules-library", file).toAbsolutePath()));
        }
        context.start();
        template = context.createProducerTemplate();
    }

    @AfterEach
    void stop() {
        context.stop();
    }

    private Exchange send(String endpoint, Map<String, Object> headers) {
        Exchange exchange = new DefaultExchange(context);
        exchange.getMessage().setHeaders(new HashMap<>(headers));
        exchange.getMessage().setBody(null);
        return template.send(endpoint, exchange);
    }

    private String body(Exchange exchange) {
        Object body = exchange.getMessage().getBody();
        return body == null ? null : body instanceof byte[] bytes ? new String(bytes, StandardCharsets.UTF_8) : body.toString();
    }

    @Test
    void stagedHttpC2RegistersThenTasksInOrder() {
        Map<String, Object> beacon = Map.of(ACTOR, "pid:42", METHOD, "GET");
        assertTrue(body(send("direct:library-staged-http-c2", beacon)).contains("\"status\":\"registered\""));
        assertTrue(body(send("direct:library-staged-http-c2", beacon)).contains("\"task\":\"whoami\""));
        assertTrue(body(send("direct:library-staged-http-c2", beacon)).contains("\"task\":\"sleep 60\""));
        assertTrue(body(send("direct:library-staged-http-c2", beacon)).contains("\"task\":\"whoami\"")); // Wraps
        // Another sample starts over
        assertTrue(body(send("direct:library-staged-http-c2", Map.of(ACTOR, "pid:43", METHOD, "GET"))).contains("registered"));
        assertTrue(body(send("direct:library-staged-http-c2", Map.of(ACTOR, "pid:42", METHOD, "POST"))).endsWith("ok"));
    }

    @Test
    void dnsTaskingCarriesBase64Tasks() {
        assertEquals("A 10.0.0.2", body(send("direct:library-dns-txt-tasking", Map.of(ACTOR, "ip:10.0.0.5", QTYPE, "A"))));
        String txt = body(send("direct:library-dns-txt-tasking", Map.of(ACTOR, "ip:10.0.0.5", QTYPE, "TXT")));
        assertEquals("whoami", new String(Base64.getDecoder().decode(txt.substring(4)), StandardCharsets.UTF_8));
    }

    @Test
    void ircBotnetTasksOnJoin() {
        Map<String, Object> meta = Map.of("command", "JOIN", "params", List.of("#bots"), "nick", "bot7");
        String reply = body(send("direct:library-irc-botnet", Map.of(META, meta)));
        assertTrue(reply.contains(" 332 bot7 #bots :!sysinfo") && reply.contains("PRIVMSG #bots :!sysinfo"), reply);
        assertNull(body(send("direct:library-irc-botnet", Map.of(META, Map.of("command", "PING")))));
    }

    @Test
    void killSwitchDomainsResolve() {
        assertEquals("A 10.0.0.250", body(send("direct:library-kill-switch", Map.of(QNAME, "Kill.Example"))));
        assertNull(body(send("direct:library-kill-switch", Map.of(QNAME, "c2.example"))));
    }

    @Test
    void recordedExchangeReplaysInOrder() {
        Map<String, Object> hello = Map.of(ACTOR, "pid:9", METHOD, "GET", HOST, "c2.recorded.example", PATH, "/api/v1/hello?bot=1");
        assertTrue(body(send("direct:decide-recorded", hello)).contains("\"status\":\"new\""));
        assertTrue(body(send("direct:decide-recorded", hello)).contains("\"cmd\":\"sysinfo\""));
        Exchange third = send("direct:decide-recorded", hello);
        assertTrue(body(third).contains("\"cmd\":\"download\""));
        assertEquals("recorded", third.getMessage().getHeader(ROUTE));
        assertTrue(body(send("direct:decide-recorded", hello)).contains("\"cmd\":\"download\"")); // The last repeats
        assertTrue(body(send("direct:decide-recorded", Map.of(ACTOR, "pid:9", METHOD, "POST", HOST, "c2.recorded.example", PATH, "/api/v1/result"))).startsWith("HTTP/1.1 204"));
        assertNull(body(send("direct:decide-recorded", Map.of(ACTOR, "pid:9", METHOD, "GET", HOST, "elsewhere.example", PATH, "/"))));
    }
}
