package lab.fakenet.daemon;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * State that rules keep about a sample across its events and protocols (bean "state"), keyed
 * by the FakenetActor header: e.g. register a bot on its first check-in, task it on the
 * next. Idle actors are forgotten after an hour; the number kept is bounded.
 *
 * <p>From Groovy: {@code def state = camelContext.registry.lookupByName('state');
 * state.increment(request.headers.FakenetActor, 'checkins')}. From Simple:
 * {@code ${bean:state?method=get(${header.FakenetActor}, 'stage')}}.
 */
public class SessionState {
    private static final long IDLE_MILLIS = 3_600_000;
    private static final int MAX_ACTORS = 10_000;
    /** Keys per actor (rules may build keys from sample data); past it, new keys are ignored */
    static final int MAX_KEYS = 1_000;

    private record Entry(Map<String, Object> values, long touched) {}

    private final ConcurrentHashMap<String, Entry> actors = new ConcurrentHashMap<>();

    private Map<String, Object> values(String actor) {
        long now = System.currentTimeMillis();
        if (actors.size() >= MAX_ACTORS && !actors.containsKey(actor)) {
            actors.entrySet().removeIf(e -> now - e.getValue().touched() > IDLE_MILLIS);
            if (actors.size() >= MAX_ACTORS) {
                // All active (a scan from spoofed sources, say): drop the least recently used tenth
                actors.entrySet().stream()
                    .sorted(java.util.Comparator.comparingLong(e -> e.getValue().touched()))
                    .limit(MAX_ACTORS / 10)
                    .map(Map.Entry::getKey)
                    .toList()
                    .forEach(actors::remove);
            }
        }
        Entry entry = actors.compute(actor, (key, old) -> new Entry(old == null ? new ConcurrentHashMap<>() : old.values(), now));
        return entry.values();
    }

    public Object get(String actor, String key) {
        return values(actor).get(key);
    }

    public Object get(String actor, String key, Object fallback) {
        return values(actor).getOrDefault(key, fallback);
    }

    public void put(String actor, String key, Object value) {
        Map<String, Object> values = values(actor);
        if (values.size() < MAX_KEYS || values.containsKey(key)) {
            values.put(key, value);
        }
    }

    /** Adds one to a counter and returns it (1 the first time; 0 when the actor has too many keys) */
    public long increment(String actor, String key) {
        Map<String, Object> values = values(actor);
        if (values.size() >= MAX_KEYS && !values.containsKey(key)) {
            return 0;
        }
        return ((Number) values.merge(key, 1L, (a, b) -> ((Number) a).longValue() + 1)).longValue();
    }

    /** Actors currently kept */
    public int size() {
        return actors.size();
    }

    public Map<String, Object> all(String actor) {
        return new LinkedHashMap<>(values(actor));
    }

    public void forget(String actor) {
        actors.remove(actor);
    }
}
