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
        assertEquals("df550b26dfd2e6b34bf9c9a0b701fc3b610783c1d198aa87a4ee8525f82e87e7", auth.sign(LinkAuth.helloText("nonce42")));
        assertEquals("3a16f8a98d04c4d3b4fe60739099b2f579949d6a0f9ab2154881a500fe373508",
            auth.sign(LinkAuth.eventText("req-1", "tcp-0000000000000001", "UElORw==")));
        assertEquals("cd9cdbbe8ac362d384c0eb0e591bf95301297bf668f0fbde4547bf8244af10d3",
            auth.sign(LinkAuth.actionText("req-1", "tcp-0000000000000001", "UE9ORwo=", false, null)));
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
