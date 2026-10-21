package lab.fakenet.daemon;

import org.apache.camel.CamelConfiguration;
import org.apache.camel.CamelContext;

/**
 * The beans the YAML routes use by name, sharing the link secret (property
 * fakenet.link.secret-file). Without one the daemon refuses to start, unless
 * fakenet.link.insecure=true says an unauthenticated link is wanted.
 */
public class DaemonConfiguration implements CamelConfiguration {
    @Override
    public void configure(CamelContext context) throws Exception {
        String secretFile = context.getPropertiesComponent().resolveProperty("fakenet.link.secret-file").orElse("");
        LinkAuth auth = LinkAuth.load(secretFile);
        if (!auth.enabled()) {
            boolean insecure = Boolean.parseBoolean(context.getPropertiesComponent().resolveProperty("fakenet.link.insecure").orElse("false"));
            if (!insecure) {
                throw new IllegalStateException("No fakenet.link.secret-file: set it to the nucleus's [daemon] secret_file (create one with "
                    + "`fakenet-nucleus --generate-secret PATH`), or set fakenet.link.insecure=true to run an unauthenticated link");
            }
            org.slf4j.LoggerFactory.getLogger(DaemonConfiguration.class)
                .warn("fakenet.link.insecure=true: the link to the nucleus is unauthenticated; any local process can pose as either side");
        }
        context.getRegistry().bind("eventIn", new EventIn(auth));
        context.getRegistry().bind("actionOut", new ActionOut(auth));
        context.getRegistry().bind("warmUp", new WarmUp());
        context.getRegistry().bind("state", new SessionState());
    }
}
