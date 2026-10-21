package lab.fakenet.daemon;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.camel.CamelContext;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.support.PluginHelper;
import org.apache.camel.support.ResourceHelper;
import org.junit.jupiter.api.Test;

/** routes/siem.yaml: the Wire Tap's records as ECS, Splunk HEC and CEF */
class SiemTest {
    private static final String RECORD = """
        {"event":{"version":2,"type":"event","request_id":"r1","session_id":"udp-0000000000000003","protocol":"dns","transport":"udp",
          "src":"10.0.2.15:5353","dst":"8.8.8.8:53","dport":53,"timestamp":"2026-10-17T00:00:00Z","payload":"",
          "meta":{"qname":"c2.evil.example","qtype":"A"},"process":{"pid":4242,"name":"bot.exe"}},
         "action":{"version":2,"type":"action","request_id":"r1","session_id":"udp-0000000000000003","response":"QSAxMC42LjYuNg==","close":false,"route":"c2-dns"}}
        """;

    private CamelContext context(Map<String, String> properties) throws Exception {
        CamelContext context = new DefaultCamelContext();
        properties.forEach(context.getPropertiesComponent()::addInitialProperty);
        PluginHelper.getRoutesLoader(context).loadRoutes(ResourceHelper.resolveResource(context, "file:" + Path.of("routes", "siem.yaml").toAbsolutePath()));
        context.start();
        return context;
    }

    @Test
    void sendsEcsSplunkAndCef() throws Exception {
        CamelContext context = context(Map.of(
            "fakenet.siem.ecs-uris", "mock:ecs", "fakenet.siem.splunk-uris", "mock:splunk",
            "fakenet.siem.splunk-token", "TOKEN", "fakenet.siem.syslog-uris", "mock:syslog"));
        MockEndpoint ecs = context.getEndpoint("mock:ecs", MockEndpoint.class);
        MockEndpoint splunk = context.getEndpoint("mock:splunk", MockEndpoint.class);
        MockEndpoint syslog = context.getEndpoint("mock:syslog", MockEndpoint.class);
        ecs.expectedMessageCount(1);
        splunk.expectedMessageCount(1);
        syslog.expectedMessageCount(1);
        context.createProducerTemplate().sendBody("direct:siem", RECORD);
        MockEndpoint.assertIsSatisfied(context);

        Map<String, Object> document = LinkSchema.JSON.readValue(ecs.getExchanges().get(0).getMessage().getBody(String.class), new TypeReference<>() {});
        assertEquals("8.8.8.8", ((Map<?, ?>) document.get("destination")).get("ip"));
        assertEquals(53, ((Map<?, ?>) document.get("destination")).get("port"));
        assertEquals("c2.evil.example", ((Map<?, ?>) ((Map<?, ?>) document.get("dns")).get("question")).get("name"));
        assertEquals("bot.exe", ((Map<?, ?>) document.get("process")).get("name"));
        assertEquals("c2-dns", ((Map<?, ?>) document.get("event")).get("action"));
        assertEquals(10, ((Map<?, ?>) document.get("fakenet")).get("response_bytes"));

        var hec = splunk.getExchanges().get(0).getMessage();
        assertEquals("Splunk TOKEN", hec.getHeader("Authorization"));
        assertTrue(hec.getBody(String.class).startsWith("{\"sourcetype\":\"fakenet:ecs\",\"event\":{"));
        String cef = syslog.getExchanges().get(0).getMessage().getBody(String.class);
        assertTrue(cef.startsWith("CEF:0|FakeNet|fakenet-hybrid|1|dns|c2-dns|3|") && cef.contains("dpt=53") && cef.contains("sproc=bot.exe"), cef);
        context.stop();
    }

    @Test
    void sendsNothingUntilConfigured() throws Exception {
        CamelContext context = context(Map.of());
        context.createProducerTemplate().sendBody("direct:siem", RECORD); // No outputs, no error
        context.stop();
    }
}
