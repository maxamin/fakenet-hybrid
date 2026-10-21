package lab.fakenet.daemon;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The link's shared-secret authentication (as the nucleus's fakenet_schema::auth):
 * lowercase hex HMAC-SHA256.
 * <ul>
 * <li>hello: over "fakenet-link-v2 hello\n{nonce}"</li>
 * <li>events and actions are sealed whole: {@code auth} is the message's last member, and
 * covers "fakenet-link-v2\n" plus the exact JSON text before it (every field)</li>
 * </ul>
 * Without a secret file the link is unauthenticated (signatures are neither checked nor sent).
 */
public final class LinkAuth {
    private final byte[] key;

    private LinkAuth(byte[] key) {
        this.key = key;
    }

    /** Loads the secret file; a blank path means "unauthenticated" */
    public static LinkAuth load(String path) throws Exception {
        if (path == null || path.isBlank()) {
            return new LinkAuth(null);
        }
        String secret = Files.readString(Path.of(path), StandardCharsets.UTF_8).trim();
        if (secret.length() < 32) {
            throw new IllegalArgumentException("The link secret in " + path + " is too short");
        }
        return new LinkAuth(secret.getBytes(StandardCharsets.UTF_8));
    }

    public boolean enabled() {
        return key != null;
    }

    public String sign(String text) {
        if (key == null) {
            return null;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(text.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** True when unauthenticated, or when the signature is right (constant-time) */
    public boolean verify(String text, Object signature) {
        if (key == null) {
            return true;
        }
        if (!(signature instanceof String hex)) {
            return false;
        }
        return MessageDigest.isEqual(sign(text).getBytes(StandardCharsets.US_ASCII), hex.getBytes(StandardCharsets.US_ASCII));
    }

    public static String helloText(String nonce) {
        return "fakenet-link-v2 hello\n" + nonce;
    }

    static final String SEALED = "fakenet-link-v2\n";
    /** {@code ,"auth":"} + 64 hex digits + {@code "}} */
    private static final int SEAL_SUFFIX = 9 + 64 + 2;

    /** The JSON object {@code json} with "auth" (its MAC) appended last; unchanged when unauthenticated */
    public String seal(String json) {
        if (key == null) {
            return json;
        }
        String trimmed = json.stripTrailing();
        String open = trimmed.endsWith("}") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
        String separator = open.stripTrailing().endsWith("{") ? "" : ",";
        return open + separator + "\"auth\":\"" + sign(SEALED + trimmed) + "\"}";
    }

    /** True when unauthenticated, or when the sealed message's MAC covers everything before auth */
    public boolean unseal(String text) {
        if (key == null) {
            return true;
        }
        String trimmed = text.stripTrailing();
        if (trimmed.length() < SEAL_SUFFIX) {
            return false;
        }
        int split = trimmed.length() - SEAL_SUFFIX;
        String suffix = trimmed.substring(split);
        if (!suffix.startsWith(",\"auth\":\"") || !suffix.endsWith("\"}")) {
            return false;
        }
        String mac = suffix.substring(9, 9 + 64);
        if (!mac.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
        return verify(SEALED + trimmed.substring(0, split) + "}", mac);
    }
}
