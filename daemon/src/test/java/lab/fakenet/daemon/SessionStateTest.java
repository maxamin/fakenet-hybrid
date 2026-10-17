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
}
