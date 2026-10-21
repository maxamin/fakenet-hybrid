package lab.fakenet.daemon;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

class AuditRecordTest {
    @Test
    void keepsAHashAndAPreviewOfThePayload() throws Exception {
        String payload = Base64.getEncoder().encodeToString("x".repeat(10_000).getBytes());
        String event = "{\"request_id\":\"r1\",\"payload\":\"" + payload + "\",\"meta\":{\"path\":\"/gate.php\"}}";
        JsonNode record = LinkSchema.JSON.readTree(AuditRecord.of(event, "{\"route\":\"c2\"}", 16));
        JsonNode audited = record.get("event");
        assertEquals(10_000, audited.get("payload_bytes").asInt());
        assertEquals(64, audited.get("payload_sha256").asText().length());
        assertEquals("x".repeat(16), new String(Base64.getDecoder().decode(audited.get("payload").asText())));
        assertTrue(audited.get("payload_truncated").asBoolean());
        assertEquals("c2", record.get("action").get("route").asText());
        assertEquals("/gate.php", audited.get("meta").get("path").asText());

        JsonNode none = LinkSchema.JSON.readTree(AuditRecord.of(event, "{}", 0)).get("event");
        assertEquals("", none.get("payload").asText());
    }
}
