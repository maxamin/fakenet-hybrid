package lab.fakenet.daemon;

import static lab.fakenet.daemon.LinkSchema.*;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;

import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.Expression;
import org.apache.camel.Processor;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.model.ChoiceDefinition;
import org.apache.camel.model.ExpressionNode;
import org.apache.camel.model.Model;
import org.apache.camel.model.ProcessorDefinition;
import org.apache.camel.model.RouteDefinition;
import org.apache.camel.model.WhenDefinition;
import org.apache.camel.model.language.ExpressionDefinition;
import org.apache.camel.support.DefaultExchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Warms the rules up so the first real decisions meet the nucleus's deadline: Groovy
 * compiles each script on first use, which can take seconds on a cold or busy JVM.
 * <ol>
 * <li>Compiles and evaluates once every Groovy expression in the loaded routes, on a
 * placeholder exchange (errors are expected and ignored: compilation is what counts).
 * Scripts should therefore be free of side effects, which rules are anyway.</li>
 * <li>Sends one placeholder event per protocol through direct:decide (no audit, no
 * reply), exercising the router, Simple predicates and the JSON path.</li>
 * </ol>
 * Runs automatically (decide-warm-up in decisions.yaml) each time the rules load.
 */
public class WarmUp implements Processor {
    private static final Logger LOG = LoggerFactory.getLogger(WarmUp.class);
    private static final List<String> PROTOCOLS = List.of("http", "dns", "raw", "smtp", "pop3", "ftp", "tftp", "irc", "imap", "ssh", "telnet", "redis", "ntp", "smb", "ldap", "rdp", "vnc", "mqtt", "coap", "websocket");

    @Override
    public void process(Exchange trigger) {
        CamelContext context = trigger.getContext();
        int scripts = 0;
        Model model = context.getCamelContextExtension().getContextPlugin(Model.class);
        for (RouteDefinition route : model.getRouteDefinitions()) {
            Deque<ProcessorDefinition<?>> pending = new ArrayDeque<>(route.getOutputs());
            while (!pending.isEmpty()) {
                ProcessorDefinition<?> node = pending.pop();
                if (node instanceof ExpressionNode expressionNode) {
                    scripts += warm(context, expressionNode.getExpression());
                }
                if (node instanceof ChoiceDefinition choice) {
                    for (WhenDefinition when : choice.getWhenClauses()) {
                        scripts += warm(context, when.getExpression());
                        pending.addAll(when.getOutputs());
                    }
                    if (choice.getOtherwise() != null) {
                        pending.addAll(choice.getOtherwise().getOutputs());
                    }
                }
                pending.addAll(node.getOutputs());
            }
        }
        try (ProducerTemplate template = context.createProducerTemplate()) {
            for (String protocol : PROTOCOLS) {
                Exchange exchange = placeholder(context, protocol);
                template.send("direct:decide", exchange);
            }
        } catch (Exception e) {
            LOG.debug("Warm-up decision failed (ignored)", e);
        }
        LOG.info("Warmed up {} Groovy scripts and {} protocols", scripts, PROTOCOLS.size());
    }

    private static int warm(CamelContext context, ExpressionDefinition definition) {
        if (definition == null || !"groovy".equals(definition.getLanguage())) {
            return 0;
        }
        try {
            Expression expression = context.resolveLanguage("groovy").createExpression(definition.getExpression());
            expression.init(context);
            expression.evaluate(placeholder(context, "raw"), Object.class);
        } catch (Exception e) {
            LOG.debug("Warm-up evaluation of a Groovy script failed (expected; it compiled)", e);
        }
        return 1;
    }

    private static Exchange placeholder(CamelContext context, String protocol) {
        Exchange exchange = new DefaultExchange(context);
        var message = exchange.getMessage();
        for (String header : List.of(REQUEST_ID, SESSION_ID, SRC, DST, TEXT, PATH, HOST, QNAME, QTYPE, METHOD, PROCESS)) {
            message.setHeader(header, "warm-up");
        }
        message.setHeader(PROTOCOL, protocol);
        message.setHeader(TRANSPORT, "tcp");
        message.setHeader(DPORT, 0);
        message.setHeader(PAYLOAD, new byte[0]);
        message.setHeader(META, Map.of());
        message.setHeader(EXPECTS_REPLY, true);
        message.setHeader(KIND, "event");
        message.setBody(null);
        return exchange;
    }
}
