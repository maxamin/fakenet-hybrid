package lab.fakenet.daemon;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class WarmUpTest {
    @Test
    void warmsUpEveryProtocolOfTheSchema() throws Exception {
        JsonNode schema = new ObjectMapper().readTree(Path.of("../schema/fakenet-link-v1.schema.json").toFile());
        List<String> protocols = new ArrayList<>();
        for (JsonNode node : schema.findValues("enum")) {
            List<String> values = new ArrayList<>();
            node.forEach(value -> values.add(value.asText()));
            if (values.contains("http") && values.contains("dns")) {
                protocols = values;
            }
        }
        assertFalse(protocols.isEmpty(), "no protocol enum in the schema");
        assertEquals(protocols.stream().sorted().toList(), WarmUp.PROTOCOLS.stream().sorted().toList());
    }
}
