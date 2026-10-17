package lab.fakenet.daemon;

import com.fasterxml.jackson.databind.ObjectMapper;

/** The fakenet-link-v1 message schema (schema/fakenet-link-v1.schema.json) and the header names routes use. */
public final class LinkSchema {
    private LinkSchema() {
    }

    public static final int VERSION = 1;
    public static final int MAX_DELAY_MS = 60_000;
    public static final ObjectMapper JSON = new ObjectMapper();

    /** "event", "hello" or "rejected" (set by EventIn) */
    public static final String KIND = "FakenetKind";
    public static final String REJECTED_REASON = "FakenetRejectedReason";

    /** The original event JSON, kept for the Wire Tap */
    public static final String EVENT_JSON = "FakenetEventJson";

    // Set by EventIn, for routing & scripts
    public static final String REQUEST_ID = "FakenetRequestId";
    public static final String SESSION_ID = "FakenetSessionId";
    public static final String SEQ = "FakenetSeq";
    public static final String PROTOCOL = "FakenetProtocol";
    public static final String TRANSPORT = "FakenetTransport";
    public static final String TLS = "FakenetTls";
    public static final String SRC = "FakenetSrc";
    public static final String DST = "FakenetDst";
    public static final String DPORT = "FakenetDport";
    public static final String PROCESS = "FakenetProcess";
    public static final String PID = "FakenetPid";
    public static final String PAYLOAD = "FakenetPayload";
    public static final String TEXT = "FakenetText";
    public static final String META = "FakenetMeta";
    public static final String EXPECTS_REPLY = "FakenetExpectsReply";
    // Copied from meta for convenience
    public static final String METHOD = "FakenetMethod";
    public static final String PATH = "FakenetPath";
    public static final String HOST = "FakenetHost";
    public static final String QNAME = "FakenetQname";
    public static final String QTYPE = "FakenetQtype";

    // Set by routes, read by ActionOut
    public static final String CLOSE = "FakenetClose";
    public static final String DELAY_MS = "FakenetDelayMs";
    public static final String ROUTE = "FakenetRoute";
}
