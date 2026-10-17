package lab.fakenet.daemon;

import org.apache.camel.main.Main;

/**
 * Starts stock Camel (camel-main). Everything else is configuration: application.properties
 * and the YAML routes in routes/, which reload when edited.
 */
public final class FakenetDaemon {
    private FakenetDaemon() {
    }

    public static void main(String[] args) throws Exception {
        Main main = new Main(FakenetDaemon.class);
        main.configure().addConfiguration(DaemonConfiguration.class);
        System.exit(main.run(args));
    }
}
