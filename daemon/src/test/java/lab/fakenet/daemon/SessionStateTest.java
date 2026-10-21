package lab.fakenet.daemon;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class SessionStateTest {
    @Test
    void keepsStatePerActor() {
        SessionState state = new SessionState();
        assertEquals(1, state.increment("pid:1", "n"));
        assertEquals(2, state.increment("pid:1", "n"));
        assertEquals(1, state.increment("pid:2", "n"));
        state.put("pid:1", "id", "BOT-1");
        assertEquals("BOT-1", state.get("pid:1", "id"));
        assertEquals("none", state.get("pid:2", "id", "none"));
        assertEquals(2, state.all("pid:1").size());
        state.forget("pid:1");
        assertNull(state.get("pid:1", "id"));
    }

    @Test
    void staysBoundedUnderManyActorsAndKeys() {
        SessionState state = new SessionState();
        for (int i = 0; i < 25_000; i++) {
            state.increment("ip:10.0." + (i / 256) + "." + (i % 256), "n");
        }
        assertTrue(state.size() <= 10_000, "actors: " + state.size());
        for (int i = 0; i < 2_000; i++) {
            state.put("pid:7", "k" + i, i);
        }
        assertEquals(SessionState.MAX_KEYS, state.all("pid:7").size());
        state.put("pid:7", "k0", "updated"); // Existing keys still change
        assertEquals("updated", state.get("pid:7", "k0"));
        assertEquals(0, state.increment("pid:7", "new-counter"));
    }
}
