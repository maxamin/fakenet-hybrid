package lab.fakenet.daemon;

import static lab.fakenet.daemon.LinkSchema.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
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

/** The shipped decisions.yaml, exercised directly: what each sample rule answers. */
class DecisionRulesTest {
    private CamelContext context;
    private ProducerTemplate template;

    @BeforeEach
    void start() throws Exception {
        context = new DefaultCamelContext();
        context.getRegistry().bind("warmUp", new WarmUp());
        context.getRegistry().bind("state", new SessionState());
        context.getPropertiesComponent().addInitialProperty("fakenet.link.host", "127.0.0.1");
        Path rules = Path.of("routes", "decisions.yaml").toAbsolutePath();
        PluginHelper.getRoutesLoader(context).loadRoutes(ResourceHelper.resolveResource(context, "file:" + rules));
        // The warm-up starts the link routes, which this test doesn't load
        context.getCamelContextExtension().getContextPlugin(org.apache.camel.model.Model.class)
            .getRouteDefinition("decide-warm-up").setAutoStartup("false");
        context.start();
        template = context.createProducerTemplate();
    }

    @AfterEach
    void stop() {
        context.stop();
    }

    private Exchange decide(String protocol, Map<String, Object> headers) {
        Exchange exchange = new DefaultExchange(context);
        exchange.getMessage().setHeader(PROTOCOL, protocol);
        exchange.getMessage().setHeader(SESSION_ID, "tcp-0000000000000007");
        exchange.getMessage().setHeaders(new java.util.HashMap<>(exchange.getMessage().getHeaders()));
        headers.forEach(exchange.getMessage()::setHeader);
        return template.send("direct:decide", exchange);
    }

    @Test
    void scriptsHttpReplies() {
        Exchange gate = decide("http", Map.of(PATH, "/gate.php?id=1", HOST, "c2.example"));
        assertEquals("c2-gate", gate.getMessage().getHeader(ROUTE));
        assertTrue(gate.getMessage().getBody(String.class).contains("id=tcp-0000000000000007;task=sleep"));
        Exchange update = decide("http", Map.of(PATH, "/check", HOST, "cdn.update.example.com"));
        assertTrue(update.getMessage().getBody(String.class).endsWith("\"url\":\"http://cdn.update.example.com/patch.exe\"}"));
        Exchange other = decide("http", Map.of(PATH, "/", HOST, "benign.example"));
        assertNull(other.getMessage().getBody()); // The nucleus's default
    }

    @Test
    void holdsAStagedConversationPerSample() {
        Map<String, Object> checkin = Map.of(PATH, "/checkin", HOST, "c2.example", ACTOR, "pid:77");
        String first = decide("http", checkin).getMessage().getBody(String.class);
        assertTrue(first.contains("registered BOT-"), first);
        String second = decide("http", checkin).getMessage().getBody(String.class);
        assertTrue(second.contains("task BOT-") && second.endsWith("sysinfo"), second);
        assertTrue(decide("http", Map.of(PATH, "/checkin", HOST, "c2.example", ACTOR, "pid:78")).getMessage().getBody(String.class).contains("registered"));
    }

    @Test
    void routesDnsAndRawTcp() {
        assertEquals("A 10.6.6.6", decide("dns", Map.of(QNAME, "beacon.c2.example")).getMessage().getBody(String.class));
        assertEquals("NXDOMAIN", decide("dns", Map.of(QNAME, "killswitch.example")).getMessage().getBody(String.class));
        Exchange hello = decide("raw", Map.of(TEXT, "HELLO bot42\n"));
        assertTrue(hello.getMessage().getBody(String.class).startsWith("WELCOME bot42 KEY="));
        assertEquals(true, hello.getMessage().getHeader(CLOSE, Boolean.class)); // YAML gives "true"; ActionOut converts
        assertEquals("PONG\n", decide("raw", Map.of(TEXT, "PING")).getMessage().getBody(String.class)); // trim: false kept the \n
    }
}
