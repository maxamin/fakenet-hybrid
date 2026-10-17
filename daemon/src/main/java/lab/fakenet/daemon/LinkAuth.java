package lab.fakenet.daemon;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The link's shared-secret authentication (same texts as the nucleus's
 * fakenet_schema::auth): lowercase hex HMAC-SHA256 over
 * <ul>
 * <li>hello: "fakenet-link-v1 hello\n{nonce}"</li>
 * <li>event: "fakenet-link-v1 event\n{request_id}\n{session_id}\n{payload base64}"</li>
 * <li>action: "fakenet-link-v1 action\n{request_id}\n{session_id}\n{response base64 or -}\n{close}\n{delay_ms or -}"</li>
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
        return "fakenet-link-v1 hello\n" + nonce;
    }

    public static String eventText(String requestId, String sessionId, String payloadBase64) {
        return "fakenet-link-v1 event\n" + requestId + "\n" + sessionId + "\n" + payloadBase64;
    }

    public static String actionText(String requestId, String sessionId, String responseBase64, boolean close, Long delayMs) {
        return "fakenet-link-v1 action\n" + requestId + "\n" + sessionId + "\n"
            + (responseBase64 == null ? "-" : responseBase64) + "\n" + close + "\n"
            + (delayMs == null ? "-" : delayMs.toString());
    }
}
