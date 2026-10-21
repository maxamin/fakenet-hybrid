package lab.fakenet.daemon;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The same vectors are checked by the nucleus (fakenet_schema tests): both sides must agree. */
class LinkAuthTest {
    static LinkAuth auth(Path dir) throws Exception {
        Path secret = dir.resolve("link.secret");
        Files.writeString(secret, "0123456789abcdef0123456789abcdef\n");
        return LinkAuth.load(secret.toString());
    }

    @Test
    void signsLikeTheNucleus(@TempDir Path dir) throws Exception {
        LinkAuth auth = auth(dir);
        assertEquals("ff24b35c3d3f7b507784ce66fb2716df6f0ba55d8d5d5b89a1d4fbd5ce7209e8", auth.sign(LinkAuth.helloText("nonce42")));
        String event = "{\"version\":2,\"type\":\"event\",\"request_id\":\"req-1\",\"session_id\":\"tcp-0000000000000001\",\"payload\":\"UElORw==\"}";
        String sealed = auth.seal(event);
        assertEquals(event.substring(0, event.length() - 1) + ",\"auth\":\"0a0efe72bc4a479c99323926e3ce6910eea50038f8ff9b27237fe980726ae88e\"}", sealed);
        assertTrue(auth.unseal(sealed));
        String action = "{\"version\":2,\"type\":\"action\",\"request_id\":\"req-1\",\"session_id\":\"tcp-0000000000000001\",\"response\":\"UE9ORwo=\",\"close\":false,\"route\":\"c2\"}";
        assertTrue(auth.seal(action).endsWith("\"auth\":\"bb6015bd0446842a83729ae706287bbc4d5cd74277646c855d20fc7f47da1b69\"}"));
    }

    @Test
    void everyFieldIsSealed(@TempDir Path dir) throws Exception {
        LinkAuth auth = auth(dir);
        String sealed = auth.seal("{\"type\":\"event\",\"protocol\":\"http\",\"meta\":{\"host\":\"c2.example\"},\"dport\":80}");
        assertTrue(auth.unseal(sealed));
        assertFalse(auth.unseal(sealed.replace("c2.example", "c3.example")));
        assertFalse(auth.unseal(sealed.replace("\"dport\":80", "\"dport\":81")));
        assertFalse(auth.unseal("{\"type\":\"event\"}"));
        assertTrue(LinkAuth.load("").unseal("{\"type\":\"event\"}")); // Unauthenticated: nothing to check
    }

    @Test
    void verifiesInConstantTimeAndRejectsShortSecrets(@TempDir Path dir) throws Exception {
        LinkAuth auth = auth(dir);
        String text = LinkAuth.helloText("n");
        assertTrue(auth.verify(text, auth.sign(text)));
        assertFalse(auth.verify(text, "00"));
        assertFalse(auth.verify(text, null));
        Path weak = dir.resolve("weak");
        Files.writeString(weak, "short");
        assertThrows(IllegalArgumentException.class, () -> LinkAuth.load(weak.toString()));
        LinkAuth open = LinkAuth.load("");
        assertFalse(open.enabled());
        assertTrue(open.verify(text, null)); // Unauthenticated link: nothing to check
        assertNull(open.sign(text));
    }
}
