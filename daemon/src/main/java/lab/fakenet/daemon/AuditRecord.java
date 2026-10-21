package lab.fakenet.daemon;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * The audit log's copy of an event and its decision (link.yaml, route audit). The nucleus's
 * events.jsonl keeps full payloads; this copy keeps the payload's length, its SHA-256 and at
 * most {@code fakenet.audit.payload-bytes} of it, so the audit log stays a fraction of the
 * traffic's size.
 */
public final class AuditRecord {
    private AuditRecord() {}

    public static String of(String eventJson, String actionJson, int payloadBytes) throws Exception {
        JsonNode event = LinkSchema.JSON.readTree(eventJson);
        if (event instanceof ObjectNode object && object.hasNonNull("payload")) {
            byte[] payload;
            try {
                payload = Base64.getDecoder().decode(object.get("payload").asText());
            } catch (IllegalArgumentException e) {
                payload = new byte[0];
            }
            object.put("payload_bytes", payload.length);
            object.put("payload_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload)));
            int kept = Math.max(0, Math.min(payloadBytes, payload.length));
            object.put("payload", Base64.getEncoder().encodeToString(Arrays.copyOf(payload, kept)));
            object.put("payload_truncated", kept < payload.length);
        }
        ObjectNode record = LinkSchema.JSON.createObjectNode();
        record.set("event", event);
        record.set("action", LinkSchema.JSON.readTree(actionJson));
        return LinkSchema.JSON.writeValueAsString(record);
    }
}
