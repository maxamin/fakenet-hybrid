package lab.fakenet.daemon;

import org.apache.camel.CamelConfiguration;
import org.apache.camel.CamelContext;

/**
 * The beans the YAML routes use by name, sharing the link secret
 * (property fakenet.link.secret-file; blank = unauthenticated link).
 */
public class DaemonConfiguration implements CamelConfiguration {
    @Override
    public void configure(CamelContext context) throws Exception {
        String secretFile = context.getPropertiesComponent().resolveProperty("fakenet.link.secret-file").orElse("");
        LinkAuth auth = LinkAuth.load(secretFile);
        if (!auth.enabled()) {
            org.slf4j.LoggerFactory.getLogger(DaemonConfiguration.class)
                .warn("No fakenet.link.secret-file: the link to the nucleus is unauthenticated");
        }
        context.getRegistry().bind("eventIn", new EventIn(auth));
        context.getRegistry().bind("actionOut", new ActionOut(auth));
        context.getRegistry().bind("warmUp", new WarmUp());
    }
}
